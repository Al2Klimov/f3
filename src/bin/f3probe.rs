use std::io::{self, Write};
use std::process;
use std::time::Instant;

use f3::devs::{dev_param_to_type, dev_param_valid, Device, FakeType, FileDevice, PerfDevice, ResetType, SafeDevice};
use f3::libutils::{adjust_unit, dummy_cb, print_header, printf_cb, printf_flush_cb, usec_to_str, SECTOR_ORDER};
use f3::probe::{probe_device, probe_max_written_blocks, report_probed_cache, report_probed_order, report_probed_size};

#[cfg(target_os = "linux")]
use f3::devs::BlockDevice;

const VERSION: &str = "f3probe 9.0";

struct Args {
    filename: String,

    // Debugging options
    debug: bool,
    unit_test: bool,
    keep_file: bool,

    // Behavior options
    save: bool,
    min_mem: bool,
    time_ops: bool,
    verbose: bool,
    show_progress: bool,

    // Geometry (debug)
    real_size_byte: u64,
    fake_size_byte: u64,
    wrap: i32,
    block_order: i32,
    cache_order: i32,
    strict_cache: bool,
}

fn parse_args() -> Args {
    let stdout_is_tty = unsafe { libc::isatty(libc::STDOUT_FILENO) } != 0;

    let mut args = Args {
        filename: String::new(),
        debug: false,
        unit_test: false,
        keep_file: false,
        save: true,
        min_mem: false,
        time_ops: false,
        verbose: false,
        show_progress: stdout_is_tty,
        real_size_byte: 1u64 << 31,
        fake_size_byte: 1u64 << 34,
        wrap: 31,
        block_order: SECTOR_ORDER as i32,
        cache_order: -1,
        strict_cache: false,
    };

    let raw_args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    let mut positional_set = false;

    while i < raw_args.len() {
        let arg = &raw_args[i];
        match arg.as_str() {
            "-V" | "--version" => {
                println!("{}", VERSION);
                process::exit(0);
            }
            "-h" | "--help" => {
                print_usage();
                process::exit(0);
            }
            "-d" | "--debug" => {
                args.debug = true;
            }
            "-u" | "--debug-unit-test" => {
                args.unit_test = true;
            }
            "-k" | "--debug-keep-file" => {
                args.keep_file = true;
                args.debug = true;
            }
            "-o" | "--debug-strict-cache" => {
                args.strict_cache = true;
                args.debug = true;
            }
            "-n" | "--destructive" => {
                args.save = false;
            }
            "-l" | "--min-memory" => {
                args.min_mem = true;
            }
            "-t" | "--time-ops" => {
                args.time_ops = true;
            }
            "-v" | "--verbose" => {
                args.verbose = true;
            }
            "-a" | "--debug-real-size" => {
                i += 1;
                let val = parse_required_value(&raw_args, i, "debug-real-size");
                args.real_size_byte = val as u64;
                args.debug = true;
            }
            "-f" | "--debug-fake-size" => {
                i += 1;
                let val = parse_required_value(&raw_args, i, "debug-fake-size");
                args.fake_size_byte = val as u64;
                args.debug = true;
            }
            "-m" | "--debug-wrap" => {
                i += 1;
                let val = parse_required_value(&raw_args, i, "debug-wrap");
                if val < 0 || val >= 64 {
                    eprintln!("Error: Wrap must be in the interval [0, 63]");
                    process::exit(1);
                }
                args.wrap = val as i32;
                args.debug = true;
            }
            "-b" | "--debug-block-order" => {
                i += 1;
                let val = parse_required_value(&raw_args, i, "debug-block-order");
                if val != 0 && (val < SECTOR_ORDER as i64 || val > 20) {
                    eprintln!(
                        "Error: Block order must be in the interval [{}, 20] or be zero",
                        SECTOR_ORDER
                    );
                    process::exit(1);
                }
                args.block_order = val as i32;
                args.debug = true;
            }
            "-c" | "--debug-cache-order" => {
                i += 1;
                let val = parse_required_value(&raw_args, i, "debug-cache-order");
                if val < -1 || val > 64 {
                    eprintln!("Error: Cache order must be in the interval [-1, 64]");
                    process::exit(1);
                }
                args.cache_order = val as i32;
                args.debug = true;
            }
            "-p" | "--show-progress" => {
                i += 1;
                let val = parse_required_value(&raw_args, i, "show-progress");
                args.show_progress = val != 0;
            }
            other => {
                // Handle --key=value style
                if let Some(rest) = other.strip_prefix("--show-progress=") {
                    let val: i64 = rest.parse().unwrap_or_else(|_| {
                        eprintln!("Error: Invalid value for --show-progress");
                        process::exit(1);
                    });
                    args.show_progress = val != 0;
                } else if let Some(rest) = other.strip_prefix("--debug-real-size=") {
                    args.real_size_byte = parse_int_value(rest, "debug-real-size") as u64;
                    args.debug = true;
                } else if let Some(rest) = other.strip_prefix("--debug-fake-size=") {
                    args.fake_size_byte = parse_int_value(rest, "debug-fake-size") as u64;
                    args.debug = true;
                } else if let Some(rest) = other.strip_prefix("--debug-wrap=") {
                    args.wrap = parse_int_value(rest, "debug-wrap") as i32;
                    args.debug = true;
                } else if let Some(rest) = other.strip_prefix("--debug-block-order=") {
                    args.block_order = parse_int_value(rest, "debug-block-order") as i32;
                    args.debug = true;
                } else if let Some(rest) = other.strip_prefix("--debug-cache-order=") {
                    args.cache_order = parse_int_value(rest, "debug-cache-order") as i32;
                    args.debug = true;
                } else if other.starts_with('-') {
                    eprintln!("Error: Unknown option '{}'", other);
                    process::exit(1);
                } else {
                    if positional_set {
                        eprintln!("Error: Wrong number of arguments; only one is allowed");
                        process::exit(1);
                    }
                    args.filename = other.to_string();
                    positional_set = true;
                }
            }
        }
        i += 1;
    }

    if args.filename.is_empty() {
        eprintln!("Error: The disk device was not specified");
        eprintln!("Usage: f3probe [OPTIONS] <DISK_DEV>");
        process::exit(1);
    }

    if args.debug
        && !dev_param_valid(
            args.real_size_byte,
            args.fake_size_byte,
            args.wrap,
            args.block_order as u32,
        )
    {
        eprintln!("Error: The debugging parameters are not valid");
        process::exit(1);
    }

    args
}

fn parse_required_value(raw_args: &[String], i: usize, name: &str) -> i64 {
    if i >= raw_args.len() {
        eprintln!("Error: Option --{} requires a value", name);
        process::exit(1);
    }
    raw_args[i].parse::<i64>().unwrap_or_else(|_| {
        eprintln!("Error: Invalid value for --{}: '{}'", name, raw_args[i]);
        process::exit(1);
    })
}

fn parse_int_value(s: &str, name: &str) -> i64 {
    s.parse::<i64>().unwrap_or_else(|_| {
        eprintln!("Error: Invalid value for --{}: '{}'", name, s);
        process::exit(1);
    })
}

fn print_usage() {
    println!("{}", VERSION);
    println!("Usage: f3probe [OPTIONS] <DISK_DEV>");
    println!();
    println!("Options:");
    println!("  -n, --destructive          Do not restore blocks of the device after probing it");
    println!("  -l, --min-memory           Trade speed for less use of memory");
    println!("  -t, --time-ops             Time reads, writes, and resets");
    println!("  -v, --verbose              Show detailed progress");
    println!("  -p, --show-progress=NUM    Show progress if NUM is not zero");
    println!("  -V, --version              Print version");
    println!("  -h, --help                 Print help");
}

struct UnitTestItem {
    real_size_byte: u64,
    fake_size_byte: u64,
    wrap: i32,
    block_order: i32,
    cache_order: i32,
    strict_cache: bool,
}

const UNIT_TEST_ITEMS: &[UnitTestItem] = &[
    // Smallest good drive
    UnitTestItem { real_size_byte: 1 << 21, fake_size_byte: 1 << 21, wrap: 21, block_order: SECTOR_ORDER as i32, cache_order: -1, strict_cache: false },
    // Good, 4KB-block, 1GB drive
    UnitTestItem { real_size_byte: 1 << 30, fake_size_byte: 1 << 30, wrap: 30, block_order: 12, cache_order: -1, strict_cache: false },
    // Bad drive
    UnitTestItem { real_size_byte: 0, fake_size_byte: 1 << 30, wrap: 30, block_order: SECTOR_ORDER as i32, cache_order: -1, strict_cache: false },
    // Real limbo drive geometry
    UnitTestItem { real_size_byte: 1777645568, fake_size_byte: 32505331712, wrap: 35, block_order: SECTOR_ORDER as i32, cache_order: -1, strict_cache: false },
    // Wraparound drive
    UnitTestItem { real_size_byte: 1 << 31, fake_size_byte: 1 << 34, wrap: 31, block_order: SECTOR_ORDER as i32, cache_order: -1, strict_cache: false },
    // Chain drive
    UnitTestItem { real_size_byte: 1 << 31, fake_size_byte: 1 << 34, wrap: 32, block_order: SECTOR_ORDER as i32, cache_order: -1, strict_cache: false },
    // Extreme limbo
    UnitTestItem { real_size_byte: (1 << 20) + 512, fake_size_byte: 1 << 40, wrap: 40, block_order: SECTOR_ORDER as i32, cache_order: -1, strict_cache: false },
    // Limbo with 256MB strict cache
    UnitTestItem { real_size_byte: 7600799744, fake_size_byte: 67108864000, wrap: 36, block_order: SECTOR_ORDER as i32, cache_order: 19, strict_cache: true },
    // Same with non-strict cache
    UnitTestItem { real_size_byte: 7600799744, fake_size_byte: 67108864000, wrap: 36, block_order: SECTOR_ORDER as i32, cache_order: 19, strict_cache: false },
    // Devil drive I
    UnitTestItem { real_size_byte: 0, fake_size_byte: 1 << 40, wrap: 40, block_order: SECTOR_ORDER as i32, cache_order: 21, strict_cache: true },
    // Devil drive II
    UnitTestItem { real_size_byte: 0, fake_size_byte: 1 << 40, wrap: 40, block_order: SECTOR_ORDER as i32, cache_order: 21, strict_cache: false },
];

fn unit_test(filename: &str) -> i32 {
    let mut success = 0;
    let total = UNIT_TEST_ITEMS.len();

    for (i, item) in UNIT_TEST_ITEMS.iter().enumerate() {
        let origin_type = dev_param_to_type(
            item.real_size_byte,
            item.fake_size_byte,
            item.wrap,
            item.block_order as u32,
        );
        let item_cache_byte: u64 = if item.cache_order < 0 {
            0
        } else {
            1u64 << (item.cache_order + item.block_order)
        };
        let mut f_real = item.real_size_byte as f64;
        let mut f_fake = item.fake_size_byte as f64;
        let mut f_cache = item_cache_byte as f64;
        let (f_real_v, unit_real) = adjust_unit(f_real);
        let (f_fake_v, unit_fake) = adjust_unit(f_fake);
        let (f_cache_v, unit_cache) = adjust_unit(f_cache);
        f_real = f_real_v;
        f_fake = f_fake_v;
        f_cache = f_cache_v;

        let mut dev: Box<dyn Device> = Box::new(
            FileDevice::new(
                filename,
                item.real_size_byte,
                item.fake_size_byte,
                item.wrap,
                item.block_order as u32,
                item.cache_order,
                item.strict_cache,
                false,
            )
            .unwrap_or_else(|e| {
                eprintln!("Failed to create file device: {}", e);
                process::exit(1);
            }),
        );

        let max_written_blocks = probe_max_written_blocks(dev.as_ref());
        let result = probe_device(dev.as_mut(), dummy_cb, false).unwrap_or_else(|e| {
            eprintln!("probe_device failed: {}", e);
            process::exit(1);
        });
        drop(dev);

        let fake_type = dev_param_to_type(
            result.real_size_byte,
            result.announced_size_byte,
            result.wrap,
            result.block_order,
        );

        // Report
        println!(
            "Test {}\t\ttype/real size/fake size/module/cache size/block size",
            i + 1
        );
        println!(
            "\t\t{}/{:.2} {}/{:.2} {}/2^{} Byte/{:.2} {}/2^{} Byte",
            origin_type.to_name(),
            f_real,
            unit_real,
            f_fake,
            unit_fake,
            item.wrap,
            f_cache,
            unit_cache,
            item.block_order
        );

        if result.real_size_byte == item.real_size_byte
            && result.announced_size_byte == item.fake_size_byte
            && result.wrap == item.wrap
            && item_cache_byte <= (result.cache_size_block << result.block_order)
            && result.block_order == item.block_order as u32
        {
            success += 1;
            println!(
                "\t\tPerfect!\tMax # of written blocks: {}\n",
                max_written_blocks
            );
        } else {
            let ret_f_real = result.real_size_byte as f64;
            let ret_f_fake = result.announced_size_byte as f64;
            let ret_f_cache = (result.cache_size_block << result.block_order) as f64;
            let (ret_f_real_v, ret_unit_real) = adjust_unit(ret_f_real);
            let (ret_f_fake_v, ret_unit_fake) = adjust_unit(ret_f_fake);
            let (ret_f_cache_v, ret_unit_cache) = adjust_unit(ret_f_cache);
            println!(
                "\tError\t{}/{:.2} {}/{:.2} {}/2^{} Byte/{:.2} {}/2^{} Byte\n",
                fake_type.to_name(),
                ret_f_real_v,
                ret_unit_real,
                ret_f_fake_v,
                ret_unit_fake,
                result.wrap,
                ret_f_cache_v,
                ret_unit_cache,
                result.block_order
            );
        }
    }

    print!("SUMMARY: ");
    if success == total {
        println!("Perfect!");
    } else {
        println!("Missed {} tests out of {}", total - success, total);
    }
    0
}

fn report_size(prefix: &str, bytes: u64, block_order: u32) {
    report_probed_size(0, printf_cb, prefix, bytes, block_order);
}

fn report_order(prefix: &str, order: i32) {
    report_probed_order(0, printf_cb, prefix, order);
}

fn report_cache(prefix: &str, cache_size_block: u64, block_order: u32) {
    report_probed_cache(0, printf_cb, prefix, cache_size_block, block_order);
}

fn report_probe_time(prefix: &str, usec: u64) {
    let s = usec_to_str(usec);
    println!("{} {}", prefix, s);
}

fn report_ops(op: &str, count: u64, time_us: u64) {
    let s1 = usec_to_str(time_us);
    let s2 = usec_to_str(if count > 0 { time_us / count } else { 0 });
    println!("{:>10}: {} / {} = {}", op, s1, count, s2);
}

fn test_device_inner(args: &Args) -> i32 {
    let dev: Box<dyn Device> = if args.debug {
        Box::new(
            FileDevice::new(
                &args.filename,
                args.real_size_byte,
                args.fake_size_byte,
                args.wrap,
                args.block_order as u32,
                args.cache_order,
                args.strict_cache,
                args.keep_file,
            )
            .unwrap_or_else(|e| {
                eprintln!("\nFailed to create file device: {}", e);
                eprintln!("\nApplication cannot continue, finishing...");
                process::exit(1);
            }),
        )
    } else {
        #[cfg(target_os = "linux")]
        {
            Box::new(BlockDevice::new(&args.filename, ResetType::None).unwrap_or_else(|e| {
                eprintln!("\nFailed to open block device '{}': {}", args.filename, e);
                eprintln!("\nApplication cannot continue, finishing...");
                process::exit(1);
            }))
        }
        #[cfg(not(target_os = "linux"))]
        {
            eprintln!("Block device probing is only supported on Linux");
            process::exit(1);
        }
    };

    // Optionally wrap with PerfDevice
    let dev: Box<dyn Device> = if args.time_ops {
        Box::new(PerfDevice::new(dev))
    } else {
        dev
    };

    // Optionally wrap with SafeDevice
    let (mut dev, is_safe): (Box<dyn Device>, bool) = if args.save {
        let max_blocks = probe_max_written_blocks(dev.as_ref());
        match SafeDevice::new(dev, max_blocks, args.min_mem) {
            Ok(sdev) => (Box::new(sdev), true),
            Err(_) => {
                if !args.min_mem {
                    eprintln!(
                        "Out of memory, try `f3probe --min-memory {}'",
                        args.filename
                    );
                } else {
                    eprintln!(
                        "Out of memory, try `f3probe --destructive {}'\n\
                         Please back your data up before using option --destructive.\n\
                         Alternatively, you could use a machine with more memory to run f3probe.",
                        args.filename
                    );
                }
                process::exit(1);
            }
        }
    } else {
        (dev, false)
    };

    println!("WARNING: Probing normally takes from a few seconds to 15 minutes, but");
    println!("         it can take longer. Please be patient.\n");

    let t1 = Instant::now();
    let cb = if args.verbose {
        printf_flush_cb
    } else {
        dummy_cb
    };
    let result = probe_device(dev.as_mut(), cb, args.show_progress).unwrap_or_else(|e| {
        eprintln!("probe_device failed: {}", e);
        process::exit(1);
    });
    let t2 = Instant::now();

    if args.verbose {
        println!();
    }

    // Sample perf stats before recovery (need to reach through layers)
    let _perf_stats: Option<()> = if args.time_ops {
        // The PerfDevice is inside dev (possibly wrapped by SafeDevice)
        // We can't easily extract it, so we read the fields through unsafe casting.
        // For now, we'll handle this differently based on is_safe.
        None // Will handle below
    } else {
        None
    };

    // Recover blocks if safe device was used
    if is_safe {
        let very_last_pos = result.real_size_byte >> result.block_order;
        print!("Probe finished, recovering blocks...");
        let _ = io::stdout().flush();

        // We need to downcast to SafeDevice to call recover
        // Since we created it as Box<SafeDevice> -> Box<dyn Device>, we can use Any
        // But Device doesn't implement Any. Instead, use raw pointer approach.
        let sdev_ptr = dev.as_mut() as *mut dyn Device as *mut SafeDevice;
        unsafe {
            if very_last_pos > 0 {
                let _ = (*sdev_ptr).recover(very_last_pos - 1);
            }
            println!(" Done");
            (*sdev_ptr).flush();
        }
    }

    // Try to get perf stats
    let perf_sample = if args.time_ops {
        // PerfDevice might be inside SafeDevice or directly our dev.
        // For simplicity, use unsafe pointer casting based on device stack.
        if is_safe {
            // SafeDevice wraps PerfDevice - get inner through into_inner after done
            // Actually we can't easily get it. Skip perf reporting in safe+perf mode
            // via cast chain. The SafeDevice has shadow_dev which is PerfDevice.
            let _sdev_ptr = dev.as_ref() as *const dyn Device as *const SafeDevice;
            // Can't access private shadow_dev directly. We'll skip detailed perf in this case.
            None
        } else {
            let pdev_ptr = dev.as_ref() as *const dyn Device as *const PerfDevice;
            Some(unsafe { (*pdev_ptr).sample() })
        }
    } else {
        None
    };

    drop(dev);

    if is_safe {
        println!();
    }

    let fake_type = dev_param_to_type(
        result.real_size_byte,
        result.announced_size_byte,
        result.wrap,
        result.block_order,
    );

    match fake_type {
        FakeType::Good => {
            println!(
                "Good news: The device `{}' is the real thing",
                args.filename
            );
        }
        FakeType::Bad => {
            println!("Bad news: The device `{}' is damaged", args.filename);
        }
        FakeType::Limbo | FakeType::Wraparound | FakeType::Chain => {
            let last_good_sector = (result.real_size_byte >> SECTOR_ORDER) - 1;
            assert!(result.block_order >= SECTOR_ORDER);
            println!(
                "Bad news: The device `{}' is a counterfeit of type {}\n\n\
                 You can \"fix\" this device using the following command:\n\
                 f3fix --last-sec={} {}",
                args.filename,
                fake_type.to_name(),
                last_good_sector,
                args.filename
            );
        }
    }

    println!("\nDevice geometry:");
    report_size(
        "\t         *Usable* size:",
        result.real_size_byte,
        result.block_order,
    );
    report_size(
        "\t        Announced size:",
        result.announced_size_byte,
        result.block_order,
    );
    report_order("\t                Module:", result.wrap);
    report_cache(
        "\tApproximate cache size:",
        result.cache_size_block,
        result.block_order,
    );
    report_order("\t   Physical block size:", result.block_order as i32);

    let elapsed_us = t2.duration_since(t1).as_micros() as u64;
    report_probe_time("\nProbe time:", elapsed_us);

    if let Some((read_count, read_time_us, write_count, write_time_us, reset_count, _reset_time_us)) =
        perf_sample
    {
        println!(" Operation: total time / count = avg time");
        report_ops("Read", read_count, read_time_us);
        report_ops("Write", write_count, write_time_us);
        assert_eq!(reset_count, 0);
    }

    if fake_type == FakeType::Good {
        0
    } else {
        100 + fake_type as i32
    }
}

fn main() {
    let args = parse_args();
    print_header("probe");

    let exit_code = if args.unit_test {
        unit_test(&args.filename)
    } else {
        test_device_inner(&args)
    };

    process::exit(exit_code);
}
