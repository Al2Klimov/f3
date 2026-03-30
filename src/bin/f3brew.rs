use clap::Parser;
use f3::devs::{self, Device, FakeType, ResetType};
use f3::flow::{DynamicBuffer, Flow};
use f3::libutils::{
    self, adjust_unit, block_state_to_str, fill_buffer_with_block, print_header,
    validate_block_update_stats, BlockState, BlockStats, SECTOR_ORDER,
};
use std::io::Write;
use std::time::SystemTime;

#[derive(Parser)]
#[command(name = "f3brew", version = f3::F3_STR_VERSION, about = "F3 Block REad and Write -- assess the media of a block device writing blocks, resetting the drive, and reading the blocks back")]
struct Args {
    /// Disk device path
    disk_dev: String,

    /// Enable debugging
    #[arg(short = 'd', long = "debug", hide = true)]
    debug: bool,

    /// Real size of the emulated drive
    #[arg(short = 'a', long = "debug-real-size", hide = true, default_value_t = 1u64 << 31)]
    real_size_byte: u64,

    /// Fake size of the emulated drive
    #[arg(short = 'f', long = "debug-fake-size", hide = true, default_value_t = 1u64 << 34)]
    fake_size_byte: u64,

    /// Wrap parameter of the emulated drive
    #[arg(short = 'm', long = "debug-wrap", hide = true, default_value_t = 31)]
    wrap: i32,

    /// Block order of the emulated drive
    #[arg(short = 'b', long = "debug-block-order", hide = true, default_value_t = SECTOR_ORDER as i32)]
    block_order: i32,

    /// Cache order of the emulated drive
    #[arg(short = 'c', long = "debug-cache-order", hide = true, default_value_t = -1)]
    cache_order: i32,

    /// Force the cache to be strict
    #[arg(short = 'o', long = "debug-strict-cache", hide = true)]
    strict_cache: bool,

    /// Don't remove file used for emulating the drive
    #[arg(short = 'k', long = "debug-keep-file", hide = true)]
    keep_file: bool,

    /// Reset method to use (0=manual USB, 1=USB, 2=none)
    #[arg(short = 's', long = "reset-type", default_value_t = 0)]
    reset_type: u8,

    /// Where test begins (block number)
    #[arg(short = 'h', long = "start-at", default_value_t = 0)]
    first_block: u64,

    /// Where test ends (block number)
    #[arg(short = 'e', long = "end-at", default_value_t = u64::MAX)]
    last_block: u64,

    /// Maximum read rate in KB/s
    #[arg(short = 'r', long = "max-read-rate", default_value_t = 0)]
    max_read_rate: i64,

    /// Maximum write rate in KB/s
    #[arg(short = 'w', long = "max-write-rate", default_value_t = 0)]
    max_write_rate: i64,

    /// Show progress if NUM is not zero
    #[arg(short = 'p', long = "show-progress", default_value_t = default_show_progress())]
    show_progress: i64,

    /// Do not write blocks
    #[arg(short = 'W', long = "do-not-write")]
    do_not_write: bool,

    /// Do not read blocks
    #[arg(short = 'R', long = "do-not-read")]
    do_not_read: bool,
}

fn default_show_progress() -> i64 {
    if unsafe { libc::isatty(libc::STDOUT_FILENO) } != 0 { 1 } else { 0 }
}

struct BlockRange {
    state: BlockState,
    block_order: i32,
    start_offset: u64,
    end_offset: u64,
    found_offset: u64,
}

fn print_block_range(range: &BlockRange) {
    let bo = range.block_order as u64;
    print!(
        "[{}] from block 0x{:x} to block 0x{:x}",
        block_state_to_str(range.state),
        range.start_offset >> bo,
        range.end_offset >> bo,
    );
    if range.state == BlockState::Overwritten {
        print!(", found block 0x{:x}", range.found_offset >> bo);
    }
    println!();
}

fn write_blocks_op(
    dev: &mut dyn Device,
    fw: &mut Flow,
    first_block: u64,
    last_block: u64,
) {
    let block_size = dev.get_block_size() as usize;
    let block_order = dev.get_block_order();
    let mut offset = first_block << block_order;
    let mut first_pos = first_block;
    let mut dbuf = DynamicBuffer::new();

    fw.start_measurement();
    while first_pos <= last_block {
        let chunk_bytes = fw.get_rem_chunk_size() as usize;
        let max_blocks = last_block - first_pos + 1;
        let blocks_to_write = std::cmp::min(
            (chunk_bytes >> block_order) as u64,
            max_blocks,
        );
        if blocks_to_write == 0 {
            break;
        }

        let buf_size = blocks_to_write as usize * block_size;
        let buf = dbuf.get_buf(buf_size);
        let buf = &mut buf[..buf_size];

        for i in 0..blocks_to_write as usize {
            let start = i * block_size;
            let end = start + block_size;
            fill_buffer_with_block(&mut buf[start..end], block_order as i32, offset, 0);
            offset += block_size as u64;
        }

        let next_pos = first_pos + blocks_to_write - 1;
        if let Err(e) = dev.write_blocks(buf, first_pos, next_pos) {
            fw.clear_progress();
            eprintln!(
                "Warning: Failed to write blocks from 0x{:x} to 0x{:x}: {}",
                first_pos, next_pos, e
            );
        }

        fw.measure(-1, (blocks_to_write << block_order) as i64);
        first_pos = next_pos + 1;
    }
    fw.end_measurement(-1);
}

fn read_blocks_op(
    dev: &mut dyn Device,
    fw: &mut Flow,
    first_block: u64,
    last_block: u64,
    stats: &mut BlockStats,
) {
    let block_size = dev.get_block_size() as usize;
    let block_order = dev.get_block_order();
    let mut expected_offset = first_block << block_order;
    let mut first_pos = first_block;
    let mut range = BlockRange {
        state: BlockState::Unknown,
        block_order: block_order as i32,
        start_offset: 0,
        end_offset: 0,
        found_offset: 0,
    };
    let mut dbuf = DynamicBuffer::new();

    fw.start_measurement();
    while first_pos <= last_block {
        let chunk_bytes = fw.get_rem_chunk_size() as usize;
        let max_blocks = last_block - first_pos + 1;
        let blocks_to_read = std::cmp::min(
            (chunk_bytes >> block_order) as u64,
            max_blocks,
        );
        if blocks_to_read == 0 {
            break;
        }

        let buf_size = blocks_to_read as usize * block_size;
        let buf = dbuf.get_buf(buf_size);
        let buf = &mut buf[..buf_size];

        let next_pos = first_pos + blocks_to_read - 1;
        if let Err(e) = dev.read_blocks(buf, first_pos, next_pos) {
            fw.clear_progress();
            eprintln!(
                "Warning: Failed to read blocks from 0x{:x} to 0x{:x}: {}",
                first_pos, next_pos, e
            );
        }

        for i in 0..blocks_to_read as usize {
            let start = i * block_size;
            let end = start + block_size;
            let mut found_offset = 0u64;
            let state = validate_block_update_stats(
                &buf[start..end],
                block_order as i32,
                expected_offset,
                &mut found_offset,
                0,
                stats,
            );

            let push_range = range.state != state
                || (state == BlockState::Overwritten
                    && (expected_offset.wrapping_sub(range.start_offset)
                        != found_offset.wrapping_sub(range.found_offset)));

            if push_range {
                if range.state != BlockState::Unknown {
                    fw.clear_progress();
                    print_block_range(&range);
                }
                range.state = state;
                range.start_offset = expected_offset;
                range.end_offset = expected_offset;
                range.found_offset = found_offset;
            } else {
                range.end_offset = expected_offset;
            }

            expected_offset += block_size as u64;
        }

        fw.measure(-1, (blocks_to_read << block_order) as i64);
        first_pos = next_pos + 1;
    }
    fw.end_measurement(-1);

    if range.state != BlockState::Unknown {
        print_block_range(&range);
    }
}

fn main() {
    let mut args = Args::parse();
    print_header("brew");

    let rt = match args.reset_type {
        0 => ResetType::ManualUsb,
        1 => ResetType::Usb,
        2 => ResetType::None,
        _ => {
            eprintln!("Reset type must be in the interval [0, 2]");
            std::process::exit(1);
        }
    };

    let mut dev: Box<dyn Device> = if args.debug {
        match devs::FileDevice::new(
            &args.disk_dev,
            args.real_size_byte,
            args.fake_size_byte,
            args.wrap,
            args.block_order,
            args.cache_order,
            args.strict_cache,
            args.keep_file,
        ) {
            Some(d) => Box::new(d),
            None => {
                eprintln!("\nApplication cannot continue, finishing...");
                std::process::exit(1);
            }
        }
    } else {
        #[cfg(target_os = "linux")]
        {
            match devs::BlockDevice::new(&args.disk_dev, rt) {
                Some(d) => Box::new(d),
                None => {
                    eprintln!("\nApplication cannot continue, finishing...");
                    std::process::exit(1);
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            eprintln!("f3brew requires Linux for block device access");
            std::process::exit(1);
        }
    };

    let block_order = dev.get_block_order();
    let block_size = dev.get_block_size();
    println!("Physical block size: 2^{} Bytes\n", block_order);

    let very_last_block = (dev.get_size_byte() >> block_order) - 1;
    if args.first_block > very_last_block {
        args.first_block = very_last_block;
    }
    if args.last_block > very_last_block {
        args.last_block = very_last_block;
    }

    let test_write = !args.do_not_write;
    let test_read = !args.do_not_read;
    let show_progress = args.show_progress != 0;

    if test_write {
        let total_size = (args.last_block - args.first_block + 1) << block_order;
        println!(
            "Writing blocks from 0x{:x} to 0x{:x}... ",
            args.first_block, args.last_block
        );
        std::io::stdout().flush().ok();

        let mut fw = Flow::new(
            block_size as i32,
            total_size,
            args.max_write_rate,
            show_progress,
            0,
            false,
        );
        let t1 = SystemTime::now();
        write_blocks_op(dev.as_mut(), &mut fw, args.first_block, args.last_block);
        let t2 = SystemTime::now();
        println!("Done");
        fw.print_measured_speed(&t1, &t2, "writing");
        println!();
    }

    if test_write && test_read {
        if let Err(e) = dev.reset() {
            eprintln!("Reset failed: {}", e);
        }
        let final_name = dev.get_filename().to_string();
        if final_name != args.disk_dev {
            println!(
                "\nWARNING: device `{}' moved to `{}' due to the reset\n",
                args.disk_dev, final_name
            );
        }
    }

    if test_read {
        let total_size = (args.last_block - args.first_block + 1) << block_order;
        println!(
            "Reading blocks from 0x{:x} to 0x{:x}:",
            args.first_block, args.last_block
        );

        let mut fw = Flow::new(
            block_size as i32,
            total_size,
            args.max_read_rate,
            show_progress,
            0,
            false,
        );
        let mut stats = BlockStats::default();
        let t1 = SystemTime::now();
        read_blocks_op(
            dev.as_mut(),
            &mut fw,
            args.first_block,
            args.last_block,
            &mut stats,
        );
        let t2 = SystemTime::now();

        libutils::print_stats(&stats, block_size as i32, "blocks");
        fw.print_measured_speed(&t1, &t2, "reading");
        println!();
    }
}
