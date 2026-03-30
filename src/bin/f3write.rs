use clap::Parser;
use f3::flow::{DynamicBuffer, Flow};
use f3::fs_utils::{adjust_dev_path, full_fn_from_number, get_block_size, ls_my_files, GIGABYTES};
use f3::libutils::{adjust_unit, dummy_cb, fill_buffer, print_header, printf_flush_cb};
use std::ffi::CString;
use std::io::{self, Write};
use std::time::Instant;

#[derive(Parser)]
#[command(name = "f3write", about = "F3 Write 9.0", version = f3::F3_STR_VERSION)]
struct Args {
    /// First NUM.h2w file to be written [default: 1]
    #[arg(short = 's', long = "start-at", value_name = "NUM")]
    start_at: Option<i64>,

    /// Last NUM.h2w file to be written [default: max]
    #[arg(short = 'e', long = "end-at", value_name = "NUM")]
    end_at: Option<i64>,

    /// Maximum write rate [default: 0 = unlimited]
    #[arg(short = 'w', long = "max-write-rate", value_name = "KB/s")]
    max_write_rate: Option<i64>,

    /// Show progress if NUM is not zero
    #[arg(short = 'p', long = "show-progress", value_name = "NUM")]
    show_progress: Option<i64>,

    /// Path to fill with .h2w files
    path: String,
}

fn get_freespace(path: &str) -> u64 {
    let c_path = CString::new(path).expect("Invalid path");
    unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        let ret = libc::statvfs(c_path.as_ptr(), &mut stat);
        assert_eq!(ret, 0, "statvfs failed for {}", path);
        stat.f_frsize as u64 * stat.f_bfree as u64
    }
}

fn pr_freespace(fs: u64) {
    let (val, unit) = adjust_unit(fs as f64);
    println!("Free space: {:.2} {}", val, unit);
}

fn flush_chunk(fd: i32) -> i32 {
    unsafe {
        if libc::fdatasync(fd) < 0 {
            return -1;
        }
        let ret = libc::posix_fadvise(fd, 0, 0, libc::POSIX_FADV_DONTNEED);
        assert_eq!(ret, 0);
    }
    0
}

fn write_all_fd(fd: i32, buf: &[u8]) -> i32 {
    let mut done = 0usize;
    while done < buf.len() {
        let rc = unsafe {
            libc::write(
                fd,
                buf[done..].as_ptr() as *const libc::c_void,
                buf.len() - done,
            )
        };
        if rc < 0 {
            return io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        }
        done += rc as usize;
    }
    0
}

fn write_chunk(dbuf: &mut DynamicBuffer, fd: i32, mut chunk_size: u64, offset: &mut u64) -> i32 {
    let buf = dbuf.get_buf(chunk_size as usize);
    let len = buf.len();

    while chunk_size > 0 {
        let turn_size = if chunk_size <= len as u64 {
            chunk_size as usize
        } else {
            len
        };
        chunk_size -= turn_size as u64;
        *offset = fill_buffer(&mut buf[..turn_size], turn_size, *offset);
        let ret = write_all_fd(fd, &buf[..turn_size]);
        if ret != 0 {
            return ret;
        }
    }
    0
}

/// Returns true when disk is full.
fn create_and_fill_file(
    path: &str,
    number: i64,
    size: u64,
    has_suggested_max_write_rate: &mut bool,
    fw: &mut Flow,
) -> bool {
    let (full_fn, filename) = full_fn_from_number(path, number);
    print!("Creating file {} ... ", filename);
    io::stdout().flush().unwrap();

    let c_path = CString::new(full_fn.to_str().unwrap()).unwrap();
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
            libc::S_IRUSR | libc::S_IWUSR,
        )
    };

    if fd < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOSPC) {
            println!("No space left.");
            return true;
        }
        eprintln!("Can't create file {}: {}", full_fn.display(), err);
        std::process::exit(1);
    }

    let mut dbuf = DynamicBuffer::new();
    let mut saved_errno = 0i32;
    let mut offset = number as u64 * GIGABYTES;
    let mut remaining = size;

    fw.start_measurement();
    while remaining > 0 {
        let mut write_size = fw.get_rem_chunk_size();
        if write_size > remaining {
            write_size = remaining;
        }
        if write_size == 0 {
            break;
        }
        saved_errno = write_chunk(&mut dbuf, fd, write_size, &mut offset);
        if saved_errno != 0 {
            break;
        }
        remaining -= write_size;
        if fw.measure(fd, write_size as i64) < 0 {
            saved_errno = io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            break;
        }
    }

    if fw.end_measurement(fd) < 0 && saved_errno == 0 {
        saved_errno = io::Error::last_os_error().raw_os_error().unwrap_or(-1);
    }

    dbuf.free();
    unsafe {
        libc::close(fd);
    }

    if saved_errno == 0 || saved_errno == libc::ENOSPC {
        if saved_errno == 0 {
            assert_eq!(remaining, 0);
        }
        println!("OK!");
        return saved_errno == libc::ENOSPC;
    }

    let err_msg = io::Error::from_raw_os_error(saved_errno);
    println!("Write failure: {}", err_msg);
    if saved_errno == libc::EIO && !*has_suggested_max_write_rate {
        *has_suggested_max_write_rate = true;
        println!(
            "\nWARNING:\n\
             The write error above may be due to your memory card overheating\n\
             under constant, maximum write rate. You can test this hypothesis\n\
             touching your memory card. If it is hot, you can try f3write\n\
             again, once your card has cooled down, using parameter --max-write-rate=2048\n\
             to limit the maximum write rate to 2MB/s, or another suitable rate.\n"
        );
    }
    false
}

fn fill_fs(
    path: &str,
    start_at: i64,
    mut end_at: i64,
    max_write_rate: i64,
    progress: bool,
) -> i32 {
    let mut free_space = get_freespace(path);
    pr_freespace(free_space);
    if free_space == 0 {
        println!("No space!");
        return 1;
    }

    let num_files = end_at - start_at + 1;
    if num_files > 0 && (num_files as u64) <= (free_space >> 30) {
        free_space = (num_files as u64) << 30;
    } else {
        end_at = start_at + (free_space >> 30) as i64;
    }

    let cb = if progress { printf_flush_cb } else { dummy_cb };
    let mut fw = Flow::new(
        get_block_size(path),
        free_space,
        max_write_rate,
        cb,
        0,
        Some(flush_chunk),
    );

    let t1 = Instant::now();
    let mut has_suggested_max_write_rate = max_write_rate > 0;
    for i in start_at..=end_at {
        if create_and_fill_file(path, i, GIGABYTES, &mut has_suggested_max_write_rate, &mut fw) {
            break;
        }
    }
    let t2 = Instant::now();

    pr_freespace(get_freespace(path));
    fw.print_measured_speed(t1, t2, "writing");

    0
}

fn unlink_old_files(path: &str, start_at: i64, end_at: i64) {
    let files = ls_my_files(path, start_at, end_at);
    for number in files {
        let (full_fn, filename) = full_fn_from_number(path, number);
        println!("Removing old file {} ...", filename);
        let c_path = CString::new(full_fn.to_str().unwrap()).unwrap();
        if unsafe { libc::unlink(c_path.as_ptr()) } != 0 {
            let err = io::Error::last_os_error();
            eprintln!("Can't remove file {}: {}", full_fn.display(), err);
            std::process::exit(1);
        }
    }
}

fn main() {
    let args = Args::parse();

    let start_at = match args.start_at {
        Some(v) => {
            if v <= 0 {
                eprintln!("error: NUM must be greater than zero");
                std::process::exit(1);
            }
            v - 1
        }
        None => 0,
    };

    let end_at = match args.end_at {
        Some(v) => {
            if v <= 0 {
                eprintln!("error: NUM must be greater than zero");
                std::process::exit(1);
            }
            v - 1
        }
        None => i64::MAX - 1,
    };

    if start_at > end_at {
        eprintln!("error: Option --start-at must be less or equal to option --end-at");
        std::process::exit(1);
    }

    let max_write_rate = match args.max_write_rate {
        Some(v) => {
            if v <= 0 {
                eprintln!("error: KB/s must be greater than zero");
                std::process::exit(1);
            }
            v
        }
        None => 0,
    };

    let show_progress = match args.show_progress {
        Some(v) => v != 0,
        None => unsafe { libc::isatty(libc::STDOUT_FILENO) != 0 },
    };

    print_header("write");

    let path = adjust_dev_path(&args.path);

    unlink_old_files(&path, start_at, end_at);

    let ret = fill_fs(&path, start_at, end_at, max_write_rate, show_progress);
    std::process::exit(ret);
}
