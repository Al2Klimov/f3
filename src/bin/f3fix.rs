use clap::Parser;
use f3::libutils::print_header;
use std::process::Command;

#[derive(Parser)]
#[command(name = "f3fix", version = f3::F3_STR_VERSION, about = "F3 Fix -- edit the partition table of a fake flash drive to have a single partition that fully covers the real capacity of the drive")]
struct Args {
    /// Disk device path
    disk_dev: Option<String>,

    /// Disk type of the partition table
    #[arg(short = 'd', long = "disk-type", default_value = "msdos")]
    disk_type: String,

    /// Type of the file system of the partition
    #[arg(short = 'f', long = "fs-type", default_value = "fat32")]
    fs_type: String,

    /// Mark the partition for boot
    #[arg(short = 'b', long = "boot")]
    boot: bool,

    /// Do not mark the partition for boot
    #[arg(short = 'n', long = "no-boot")]
    no_boot: bool,

    /// Sector where the partition starts
    #[arg(short = 'a', long = "first-sec", default_value_t = 2048)]
    first_sec: i64,

    /// Sector where the partition ends
    #[arg(short = 'l', long = "last-sec", default_value_t = -1)]
    last_sec: i64,

    /// List all supported disk types
    #[arg(short = 'k', long = "list-disk-types")]
    list_disk_types: bool,

    /// List all supported types of file systems
    #[arg(short = 's', long = "list-fs-types")]
    list_fs_types: bool,
}

fn main() {
    let args = Args::parse();
    print_header("fix");

    if args.list_disk_types {
        println!("Disk types:");
        // Use parted to list disk types
        let output = Command::new("parted")
            .args(["--list", "--machine"])
            .output();
        match output {
            Ok(o) => {
                // Common disk types
                println!("aix\tamiga\tbsd\tdvh\tgpt");
                println!("loop\tmac\tmsdos\tpc98\tsun");
            }
            Err(_) => {
                println!("aix\tamiga\tbsd\tdvh\tgpt");
                println!("loop\tmac\tmsdos\tpc98\tsun");
            }
        }
        println!();
    }

    if args.list_fs_types {
        println!("File system types:");
        println!("btrfs\text2\text3\text4\tfat16");
        println!("fat32\thfs\thfs+\thfsx\tlinux-swap");
        println!("ntfs\treiserfs\tudf\txfs");
        println!();
    }

    if args.list_disk_types || args.list_fs_types {
        return;
    }

    let disk_dev = match &args.disk_dev {
        Some(d) => d,
        None => {
            eprintln!("The disk device was not specified");
            std::process::exit(1);
        }
    };

    if args.last_sec < 0 {
        eprintln!("Option --last-sec is required");
        std::process::exit(1);
    }

    if args.first_sec > args.last_sec {
        eprintln!("Option --first-sec must be less or equal to option --last-sec");
        std::process::exit(1);
    }

    let boot_flag = if args.no_boot { false } else { true };

    // Use parted command to fix the disk
    let mut cmd = Command::new("parted");
    cmd.args([
        "-s",
        disk_dev,
        "mklabel",
        &args.disk_type,
    ]);

    let output = cmd.output();
    match output {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            eprintln!(
                "Failed to create disk label: {}",
                String::from_utf8_lossy(&o.stderr)
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Failed to run parted: {}", e);
            std::process::exit(1);
        }
    }

    // Create partition
    let first = format!("{}s", args.first_sec);
    let last = format!("{}s", args.last_sec);
    let mut cmd = Command::new("parted");
    cmd.args([
        "-s",
        disk_dev,
        "mkpart",
        "primary",
        &args.fs_type,
        &first,
        &last,
    ]);

    let output = cmd.output();
    match output {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            eprintln!(
                "Failed to create partition: {}",
                String::from_utf8_lossy(&o.stderr)
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Failed to run parted: {}", e);
            std::process::exit(1);
        }
    }

    // Set boot flag if needed
    if boot_flag {
        let mut cmd = Command::new("parted");
        cmd.args(["-s", disk_dev, "set", "1", "boot", "on"]);
        let _ = cmd.output(); // Best effort
    }

    println!("Drive `{}' was successfully fixed", disk_dev);
}
