use clap::Parser;
use f3::flow::{DynamicBuffer, Flow};
use f3::fs_utils::{adjust_dev_path, full_fn_from_number, get_block_size, ls_my_files, GIGABYTES};
use f3::libutils::{
    dummy_cb, print_header, printf_flush_cb, BlockStats, SECTOR_ORDER, SECTOR_SIZE,
};
use std::ffi::CString;
use std::io::{self, Write};
use std::time::Instant;

#[derive(Parser)]
#[command(name = "f3read", about = "F3 Read 9.0", version = f3::F3_STR_VERSION)]
struct Args {
    /// First NUM.h2w file to be read [default: 1]
    #[arg(short = 's', long = "start-at", value_name = "NUM")]
    start_at: Option<i64>,

    /// Last NUM.h2w file to be read [default: max]
    #[arg(short = 'e', long = "end-at", value_name = "NUM")]
    end_at: Option<i64>,

    /// Maximum read rate [default: 0 = unlimited]
    #[arg(short = 'r', long = "max-read-rate", value_name = "KB/s")]
    max_read_rate: Option<i64>,

    /// Show progress if NUM is not zero
    #[arg(short = 'p', long = "show-progress", value_name = "NUM")]
    show_progress: Option<i64>,

    /// Path containing .h2w files
    path: String,
}

struct FileStats {
    secs: BlockStats,
    bytes_read: u64,
    read_all: bool,
}

impl FileStats {
    fn new() -> Self {
        Self {
            secs: BlockStats::new(),
            bytes_read: 0,
            read_all: false,
        }
    }
}

fn read_all_fd(fd: i32, buf: &mut [u8], count: usize) -> isize {
    let mut done = 0usize;
    while done < count {
        let rc = unsafe {
            libc::read(
                fd,
                buf[done..].as_mut_ptr() as *mut libc::c_void,
                count - done,
            )
        };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return -(e.raw_os_error().unwrap_or(1) as isize);
        }
        if rc == 0 {
            break;
        }
        done += rc as usize;
    }
    done as isize
}

fn check_buffer(buf: &[u8], size: usize, mut expected_offset: u64, stats: &mut FileStats) -> u64 {
    assert!(size % SECTOR_SIZE == 0);
    let mut pos = 0;
    while pos < size {
        f3::libutils::validate_block_update_stats(
            &buf[pos..pos + SECTOR_SIZE],
            SECTOR_ORDER,
            expected_offset,
            0,
            &mut stats.secs,
        );
        pos += SECTOR_SIZE;
        expected_offset += SECTOR_SIZE as u64;
    }
    expected_offset
}

fn check_chunk(
    dbuf: &mut DynamicBuffer,
    fd: i32,
    expected_offset: &mut u64,
    chunk_size: u64,
    stats: &mut FileStats,
) -> isize {
    let buf = dbuf.get_buf(chunk_size as usize);
    let len = buf.len();
    let mut tot_bytes_read: isize = 0;
    let mut remaining = chunk_size;

    while remaining > 0 {
        let turn_size = if remaining <= len as u64 {
            remaining as usize
        } else {
            len
        };
        let bytes_read = read_all_fd(fd, buf, turn_size);
        if bytes_read < 0 {
            stats.bytes_read += tot_bytes_read as u64;
            return bytes_read;
        }
        if bytes_read == 0 {
            break;
        }
        tot_bytes_read += bytes_read;
        remaining -= bytes_read as u64;
        *expected_offset =
            check_buffer(&buf[..bytes_read as usize], bytes_read as usize, *expected_offset, stats);
    }

    stats.bytes_read += tot_bytes_read as u64;
    tot_bytes_read
}

fn print_status(stats: &FileStats) {
    print!(
        "{:7}/{:9}/{:7}/{:7}",
        stats.secs.ok, stats.secs.bad, stats.secs.changed, stats.secs.overwritten
    );
}

fn validate_file(path: &str, number: i64, fw: &mut Flow, stats: &mut FileStats) {
    *stats = FileStats::new();

    let (full_fn, filename) = full_fn_from_number(path, number);
    print!("Validating file {} ... ", filename);
    io::stdout().flush().unwrap();

    let c_path = CString::new(full_fn.to_str().unwrap()).unwrap();
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        let err = io::Error::last_os_error();
        eprintln!("Can't open file {}: {}", full_fn.display(), err);
        std::process::exit(err.raw_os_error().unwrap_or(1));
    }

    // Flush kernel cache so we measure real device read speed
    let sync_ret = unsafe { libc::fdatasync(fd) };
    if sync_ret < 0 {
        let saved_errno = io::Error::last_os_error();
        println!(
            "\nWARNING:\n\
             The operating system returned errno={} for fdatasync(): {}\n\
             This error is unexpected and you may find more information \
             on the log of the kernel (e.g. command dmesg(1) on Linux).\n",
            saved_errno.raw_os_error().unwrap_or(0),
            saved_errno
        );
        std::process::exit(saved_errno.raw_os_error().unwrap_or(1));
    }
    unsafe {
        assert_eq!(
            libc::posix_fadvise(fd, 0, 0, libc::POSIX_FADV_DONTNEED),
            0
        );
        assert_eq!(
            libc::posix_fadvise(fd, 0, 0, libc::POSIX_FADV_SEQUENTIAL),
            0
        );
    }

    let mut dbuf = DynamicBuffer::new();
    let mut saved_errno = 0i32;
    let mut expected_offset = number as u64 * GIGABYTES;
    let mut hit_eof = false;

    fw.start_measurement();
    loop {
        let chunk_size = fw.get_rem_chunk_size();
        let bytes_read =
            check_chunk(&mut dbuf, fd, &mut expected_offset, chunk_size, stats);
        if bytes_read == 0 {
            hit_eof = true;
            break;
        }
        if bytes_read < 0 {
            saved_errno = (-bytes_read) as i32;
            break;
        }
        if fw.measure(fd, bytes_read as i64) < 0 {
            saved_errno = io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            break;
        }
    }
    if fw.end_measurement(fd) < 0 && saved_errno == 0 {
        saved_errno = io::Error::last_os_error().raw_os_error().unwrap_or(-1);
    }

    print_status(stats);
    stats.read_all = hit_eof;
    if !stats.read_all {
        assert!(saved_errno != 0);
        let err_msg = io::Error::from_raw_os_error(saved_errno);
        print!(" - NOT fully read due to \"{}\"", err_msg);
    } else if saved_errno != 0 {
        let err_msg = io::Error::from_raw_os_error(saved_errno);
        print!(" - {}", err_msg);
    }
    println!();

    dbuf.free();
    unsafe {
        libc::close(fd);
    }
}

fn get_total_size(path: &str, files: &[i64]) -> u64 {
    let mut total_size: u64 = 0;
    for &file_num in files {
        let (full_fn, _) = full_fn_from_number(path, file_num);
        let c_path = CString::new(full_fn.to_str().unwrap()).unwrap();
        unsafe {
            let mut st: libc::stat = std::mem::zeroed();
            let ret = libc::stat(c_path.as_ptr(), &mut st);
            if ret < 0 {
                let err = io::Error::last_os_error();
                eprintln!("Can't stat file {}: {}", full_fn.display(), err);
                std::process::exit(err.raw_os_error().unwrap_or(1));
            }
            assert!((st.st_mode & libc::S_IFMT) == libc::S_IFREG);
            assert!(st.st_size >= 0);
            total_size += st.st_size as u64;
        }
    }
    total_size
}

fn iterate_files(
    path: &str,
    files: &[i64],
    start_at: i64,
    _end_at: i64,
    max_read_rate: i64,
    progress: bool,
) {
    let mut tot_stats = BlockStats::new();
    let mut tot_size: u64 = 0;
    let mut and_read_all = true;
    let mut or_missing_file = false;
    let mut number = start_at;

    let cb = if progress { printf_flush_cb } else { dummy_cb };
    let total_size = get_total_size(path, files);
    let mut fw = Flow::new(get_block_size(path), total_size, max_read_rate, cb, 0, None);

    println!(
        "                  SECTORS \
         ok/corrupted/changed/overwritten"
    );

    let t1 = Instant::now();
    for &file_num in files {
        or_missing_file = or_missing_file || (file_num != number);
        while number < file_num {
            let (_, filename) = full_fn_from_number("", number);
            println!("Missing file {}", filename);
            number += 1;
        }
        number += 1;

        let mut stats = FileStats::new();
        validate_file(path, file_num, &mut fw, &mut stats);
        tot_stats.ok += stats.secs.ok;
        tot_stats.bad += stats.secs.bad;
        tot_stats.changed += stats.secs.changed;
        tot_stats.overwritten += stats.secs.overwritten;
        tot_size += stats.bytes_read;
        and_read_all = and_read_all && stats.read_all;
    }
    let t2 = Instant::now();

    assert_eq!(
        tot_size,
        SECTOR_SIZE as u64
            * (tot_stats.ok + tot_stats.bad + tot_stats.changed + tot_stats.overwritten)
    );

    tot_stats.print(SECTOR_SIZE, "sectors");
    if or_missing_file {
        println!(
            "WARNING: Not all F3 files in the range {} to {} are available",
            start_at + 1,
            number
        );
    }
    if !and_read_all {
        println!("WARNING: Not all data was read due to I/O error(s)");
    }

    fw.print_measured_speed(t1, t2, "reading");
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

    let max_read_rate = match args.max_read_rate {
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

    print_header("read");

    let path = adjust_dev_path(&args.path);

    let files = ls_my_files(&path, start_at, end_at);

    iterate_files(&path, &files, start_at, end_at, max_read_rate, show_progress);
}
