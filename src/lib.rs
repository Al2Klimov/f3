//! F3 (Fight Flash Fraud) - Rust library for detecting counterfeit flash drives.
//!
//! This is a Rust rewrite of the F3 C project. It provides modules for:
//! - Block filling/validation with LCG-based deterministic data
//! - Adaptive throughput control and progress reporting
//! - Filesystem utilities for .h2w test files
//! - Device abstraction (file, block, performance, safe devices)
//! - Probing algorithms for capacity detection

pub const F3_STR_VERSION: &str = "9.0";

pub mod libutils {
    //! Core utilities: LCG RNG, block fill/validate, unit formatting, statistics.

    use std::fmt;
    use std::time::Duration;

    pub const SECTOR_SIZE: usize = 512;
    pub const SECTOR_ORDER: u32 = 9;

    pub const USEC_IN_A_MSEC: u64 = 1_000;
    pub const USEC_IN_A_SEC: u64 = 1_000 * USEC_IN_A_MSEC;
    pub const USEC_IN_A_MIN: u64 = 60 * USEC_IN_A_SEC;
    pub const USEC_IN_AN_HOUR: u64 = 60 * USEC_IN_A_MIN;
    pub const USEC_IN_A_DAY: u64 = 24 * USEC_IN_AN_HOUR;

    /// Linear Congruential Generator: next = current * 4294967311 + 17
    /// This is the core RNG used for block filling/validation.
    #[inline]
    pub fn next_random_number(random_number: u64) -> u64 {
        random_number.wrapping_mul(4294967311u64).wrapping_add(17)
    }

    /// Count the number of set bits (population count / Hamming weight).
    fn pop(mut x: u64) -> i32 {
        let mut n = 0i32;
        while x != 0 {
            n += 1;
            x &= x - 1;
        }
        n
    }

    /// Floor of log base 2 of x. Undefined for x == 0.
    pub fn ilog2(mut x: u64) -> i32 {
        x |= x >> 1;
        x |= x >> 2;
        x |= x >> 4;
        x |= x >> 8;
        x |= x >> 16;
        x |= x >> 32;
        pop(x) - 1
    }

    /// Least power of 2 greater than or equal to x.
    pub fn clp2(mut x: u64) -> u64 {
        x = x.wrapping_sub(1);
        x |= x >> 1;
        x |= x >> 2;
        x |= x >> 4;
        x |= x >> 8;
        x |= x >> 16;
        x |= x >> 32;
        x.wrapping_add(1)
    }

    /// Ceiling log2: ilog2(clp2(x)).
    #[inline]
    pub fn ceiling_log2(x: u64) -> i32 {
        ilog2(clp2(x))
    }

    /// Alignment head: (1 << order) - 1.
    #[inline]
    pub fn align_head(order: u32) -> usize {
        (1usize << order) - 1
    }

    /// Align a byte offset upward to a given power-of-2 order.
    #[inline]
    pub fn align_offset(offset: usize, order: u32) -> (usize, usize) {
        let head = align_head(order);
        let aligned = (offset + head) & !head;
        (aligned, aligned - offset)
    }

    /// Unit names for adjust_unit.
    const UNITS: [&str; 7] = ["Byte", "KB", "MB", "GB", "TB", "PB", "EB"];

    /// Divide bytes by 1024 until < 1024 (or EB reached). Returns (value, unit_name).
    pub fn adjust_unit(mut bytes: f64) -> (f64, &'static str) {
        let mut i = 0usize;
        while i < 6 && bytes >= 1024.0 {
            bytes /= 1024.0;
            i += 1;
        }
        (bytes, UNITS[i])
    }

    /// Format microseconds into a human-readable string.
    pub fn usec_to_str(mut usec: u64) -> String {
        let mut result = String::new();

        let has_d = usec >= USEC_IN_A_DAY;
        if has_d {
            let days = usec / USEC_IN_A_DAY;
            usec %= USEC_IN_A_DAY;
            result.push_str(&format!("{} days", days));
        }

        let has_h = usec >= USEC_IN_AN_HOUR;
        if has_h {
            let hours = usec / USEC_IN_AN_HOUR;
            usec %= USEC_IN_AN_HOUR;
            if has_d {
                result.push(' ');
            }
            result.push_str(&format!("{}:", hours));
        }

        let has_m = has_h || usec >= USEC_IN_A_MIN;
        if has_m {
            let mins = usec / USEC_IN_A_MIN;
            usec %= USEC_IN_A_MIN;
            if has_h {
                result.push_str(&format!("{:02}", mins));
            } else {
                result.push_str(&format!("{}'", mins));
            }
        }

        let has_s = usec >= USEC_IN_A_SEC;
        if has_s {
            let secs = usec / USEC_IN_A_SEC;
            usec %= USEC_IN_A_SEC;
            if has_h {
                result.push_str(&format!(":{:02}", secs));
            } else if has_m {
                result.push_str(&format!("{:02}\"", secs));
            } else if has_d {
                result.push_str(&format!("{}s", secs));
            } else {
                let centisecs = usec / (10 * USEC_IN_A_MSEC);
                result.push_str(&format!("{}.{:02}s", secs, centisecs));
            }
        }

        if has_d || has_h || has_m || has_s {
            return result;
        }

        if usec >= USEC_IN_A_MSEC {
            let ms = usec / USEC_IN_A_MSEC;
            let remainder = usec % USEC_IN_A_MSEC;
            result.push_str(&format!("{}.{}ms", ms, remainder / 100));
        } else {
            result.push_str(&format!("{}us", usec));
        }

        result
    }

    /// Fill a buffer with deterministic block data for probe/brew operations.
    ///
    /// - First 8 bytes: raw byte offset (native endian)
    /// - Remaining 8-byte words: LCG sequence seeded with `offset ^ salt`
    /// - `block_order` must be >= SECTOR_ORDER (9)
    pub fn fill_buffer_with_block(buf: &mut [u8], block_order: u32, offset: u64, salt: u64) {
        assert!(block_order >= SECTOR_ORDER);
        let num_u64 = 1usize << (block_order - 3);
        assert!(buf.len() >= num_u64 * 8);

        let int64_slice = unsafe {
            std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u64, num_u64)
        };

        // First word: raw offset (unencrypted, known by drives).
        int64_slice[0] = offset;

        // Remaining words: LCG sequence seeded with offset ^ salt.
        let mut rng = offset ^ salt;
        for i in 1..num_u64 {
            rng = next_random_number(rng);
            int64_slice[i] = rng;
        }
    }

    /// Block validation result.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BlockState {
        Unknown,
        Good,
        Bad,
        Changed,
        Overwritten,
    }

    impl fmt::Display for BlockState {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                BlockState::Unknown => write!(f, "Unknown"),
                BlockState::Good => write!(f, "Good"),
                BlockState::Bad => write!(f, "Bad"),
                BlockState::Changed => write!(f, "Changed"),
                BlockState::Overwritten => write!(f, "Overwritten"),
            }
        }
    }

    /// Statistics for block validation results.
    #[derive(Debug, Clone, Default)]
    pub struct BlockStats {
        pub ok: u64,
        pub bad: u64,
        pub changed: u64,
        pub overwritten: u64,
    }

    impl BlockStats {
        pub fn new() -> Self {
            Self::default()
        }

        /// Print statistics in the same format as the C version.
        pub fn print(&self, block_size: usize, unit_name: &str) {
            fn print_stat(prefix: &str, count: u64, block_size: usize, unit_name: &str) {
                let bytes = count as f64 * block_size as f64;
                let (val, unit) = adjust_unit(bytes);
                println!("{} {:.2} {} ({} {})", prefix, val, unit, count, unit_name);
            }

            print_stat("\n  Data OK:", self.ok, block_size, unit_name);
            print_stat(
                "Data LOST:",
                self.bad + self.changed + self.overwritten,
                block_size,
                unit_name,
            );
            print_stat("\t       Corrupted:", self.bad, block_size, unit_name);
            print_stat("\tSlightly changed:", self.changed, block_size, unit_name);
            print_stat("\t     Overwritten:", self.overwritten, block_size, unit_name);
        }
    }

    /// Validate a buffer against expected deterministic block data.
    ///
    /// Reads the first 8 bytes as `found_offset`, then checks the LCG sequence
    /// seeded with `found_offset ^ salt`. Allows up to 2 errors (tolerance).
    ///
    /// Returns (BlockState, found_offset).
    pub fn validate_buffer_with_block(
        buf: &[u8],
        block_order: u32,
        expected_offset: u64,
        salt: u64,
    ) -> (BlockState, u64) {
        assert!(block_order >= SECTOR_ORDER);
        let num_u64 = 1usize << (block_order - 3);
        assert!(buf.len() >= num_u64 * 8);

        let int64_slice = unsafe {
            std::slice::from_raw_parts(buf.as_ptr() as *const u64, num_u64)
        };

        let found_offset = int64_slice[0];
        let mut rng = found_offset ^ salt;
        let tolerance = 2;
        let mut error_count = 0;

        for i in 1..num_u64 {
            rng = next_random_number(rng);
            if int64_slice[i] != rng {
                error_count += 1;
                if error_count > tolerance {
                    break;
                }
            }
        }

        let state = if expected_offset == found_offset {
            if error_count == 0 {
                BlockState::Good
            } else if error_count <= tolerance {
                BlockState::Changed
            } else {
                BlockState::Bad
            }
        } else if error_count <= tolerance {
            BlockState::Overwritten
        } else {
            BlockState::Bad
        };

        (state, found_offset)
    }

    /// Validate and update statistics.
    pub fn validate_block_update_stats(
        buf: &[u8],
        block_order: u32,
        expected_offset: u64,
        salt: u64,
        stats: &mut BlockStats,
    ) -> (BlockState, u64) {
        let (state, found_offset) =
            validate_buffer_with_block(buf, block_order, expected_offset, salt);

        match state {
            BlockState::Good => stats.ok += 1,
            BlockState::Changed => stats.changed += 1,
            BlockState::Bad => stats.bad += 1,
            BlockState::Overwritten => stats.overwritten += 1,
            BlockState::Unknown => {}
        }

        (state, found_offset)
    }

    /// Fill a buffer sector-by-sector for f3write.
    ///
    /// Unlike fill_buffer_with_block, this works per-sector (512 bytes) and
    /// seeds the LCG from the sector's first word (the offset itself, NOT offset^salt).
    /// Returns the next offset after the filled region.
    pub fn fill_buffer(buf: &mut [u8], size: usize, mut offset: u64) -> u64 {
        let num_u64_per_sector = SECTOR_SIZE / 8;
        assert!(size > 0);
        assert!(size % SECTOR_SIZE == 0);
        assert!(buf.len() >= size);

        let mut pos = 0;
        while pos < size {
            let sector = unsafe {
                std::slice::from_raw_parts_mut(
                    buf[pos..].as_mut_ptr() as *mut u64,
                    num_u64_per_sector,
                )
            };
            sector[0] = offset;
            for i in 1..num_u64_per_sector {
                sector[i] = next_random_number(sector[i - 1]);
            }
            pos += SECTOR_SIZE;
            offset += SECTOR_SIZE as u64;
        }

        offset
    }

    /// Print the F3 header.
    pub fn print_header(name: &str) {
        eprintln!(
            "F3 {} {}\n\
             Copyright (C) 2010 Digirati Internet LTDA.\n\
             This is free software; see the source for copying conditions.\n",
            name,
            crate::F3_STR_VERSION
        );
    }

    /// Parse a size argument with unit suffix (s, k, m, g, t).
    pub fn arg_to_ll_bytes(arg: &str) -> Result<i64, String> {
        let arg = arg.trim();
        if arg.is_empty() {
            return Err("An integer must be provided".to_string());
        }

        let (num_str, shift) = if let Some(last) = arg.chars().last() {
            match last.to_ascii_lowercase() {
                's' => (&arg[..arg.len() - 1], SECTOR_ORDER),
                'k' => (&arg[..arg.len() - 1], 10),
                'm' => (&arg[..arg.len() - 1], 20),
                'g' => (&arg[..arg.len() - 1], 30),
                't' => (&arg[..arg.len() - 1], 40),
                _ => (arg, 0),
            }
        } else {
            (arg, 0)
        };

        let val: i64 = num_str
            .parse()
            .map_err(|_| format!("`{}` is not an integer", arg))?;
        Ok(val << shift)
    }

    /// Compute the diff of two `std::time::Duration` values in nanoseconds.
    #[inline]
    pub fn diff_duration_ns(t1: Duration, t2: Duration) -> u64 {
        t2.saturating_sub(t1).as_nanos() as u64
    }

    /// Progress callback type.
    pub type ProgressCb = fn(indent: u32, msg: &str);

    /// Default progress callback: prints with indentation.
    pub fn printf_cb(indent: u32, msg: &str) {
        let indent_str = "        ";
        if msg.starts_with('\x08') {
            print!("{}", msg);
            for _ in 0..indent {
                print!("\x08\x08\x08\x08\x08\x08\x08\x08");
            }
        } else {
            for _ in 0..indent {
                print!("{}", indent_str);
            }
            print!("{}", msg);
        }
    }

    /// Flushing progress callback.
    pub fn printf_flush_cb(indent: u32, msg: &str) {
        printf_cb(indent, msg);
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }

    /// Dummy progress callback (no output).
    pub fn dummy_cb(_indent: u32, _msg: &str) {}

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_lcg() {
            let v0 = 0u64;
            let v1 = next_random_number(v0);
            assert_eq!(v1, 17);
            let v2 = next_random_number(v1);
            assert_eq!(v2, 17u64.wrapping_mul(4294967311).wrapping_add(17));
        }

        #[test]
        fn test_ilog2() {
            assert_eq!(ilog2(1), 0);
            assert_eq!(ilog2(2), 1);
            assert_eq!(ilog2(3), 1);
            assert_eq!(ilog2(4), 2);
            assert_eq!(ilog2(512), 9);
            assert_eq!(ilog2(1024), 10);
        }

        #[test]
        fn test_clp2() {
            assert_eq!(clp2(1), 1);
            assert_eq!(clp2(2), 2);
            assert_eq!(clp2(3), 4);
            assert_eq!(clp2(5), 8);
            assert_eq!(clp2(512), 512);
            assert_eq!(clp2(513), 1024);
        }

        #[test]
        fn test_adjust_unit() {
            let (val, unit) = adjust_unit(1024.0);
            assert_eq!(unit, "KB");
            assert!((val - 1.0).abs() < 1e-10);

            let (val, unit) = adjust_unit(1024.0 * 1024.0);
            assert_eq!(unit, "MB");
            assert!((val - 1.0).abs() < 1e-10);
        }

        #[test]
        fn test_fill_validate_block() {
            let block_order = 9u32; // 512 bytes
            let offset = 4096u64;
            let salt = 0xDEADBEEFu64;
            let mut buf = vec![0u8; 512];

            fill_buffer_with_block(&mut buf, block_order, offset, salt);

            let (state, found) =
                validate_buffer_with_block(&buf, block_order, offset, salt);
            assert_eq!(state, BlockState::Good);
            assert_eq!(found, offset);

            // Wrong expected offset -> Overwritten
            let (state, _) =
                validate_buffer_with_block(&buf, block_order, offset + 512, salt);
            assert_eq!(state, BlockState::Overwritten);
        }

        #[test]
        fn test_fill_buffer_f3write() {
            let mut buf = vec![0u8; 1024];
            let offset = 0u64;
            let new_offset = fill_buffer(buf.as_mut_slice(), 1024, offset);
            assert_eq!(new_offset, 1024);

            // Check first sector: first 8 bytes should be offset 0
            let first_word = u64::from_ne_bytes(buf[0..8].try_into().unwrap());
            assert_eq!(first_word, 0);

            // Second sector: first 8 bytes should be offset 512
            let second_word =
                u64::from_ne_bytes(buf[512..520].try_into().unwrap());
            assert_eq!(second_word, 512);
        }

        #[test]
        fn test_arg_to_ll_bytes() {
            assert_eq!(arg_to_ll_bytes("100").unwrap(), 100);
            assert_eq!(arg_to_ll_bytes("1k").unwrap(), 1024);
            assert_eq!(arg_to_ll_bytes("1K").unwrap(), 1024);
            assert_eq!(arg_to_ll_bytes("2m").unwrap(), 2 * 1024 * 1024);
            assert_eq!(arg_to_ll_bytes("1g").unwrap(), 1024 * 1024 * 1024);
        }
    }
}

pub mod flow {
    //! Throughput control, dynamic buffer, and progress reporting.

    use std::time::Instant;

    use crate::libutils::{self, ProgressCb, SECTOR_SIZE};

    /// Flow control states for adaptive throughput.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FlowState {
        Inc,
        Dec,
        Search,
        Steady,
    }

    /// Callback type for flushing a chunk (e.g., fdatasync).
    pub type FlushChunkFn = fn(fd: i32) -> i32;

    /// Adaptive throughput controller.
    ///
    /// Implements a 4-state machine (Inc/Dec/Search/Steady) that dynamically
    /// adjusts the number of blocks processed per measurement interval.
    pub struct Flow {
        // Configuration
        pub total_size: u64,
        pub total_processed: u64,
        pub cb: ProgressCb,
        pub indent: u32,
        pub block_size: i32,
        pub delay_ns: u64,
        pub step: i64,
        pub blocks_per_delay: i64,
        pub max_process_rate: f64,

        // Measurement accumulators
        pub measured_blocks: u64,
        pub measured_time_ns: u64,
        pub state: FlowState,
        pub erase: i32,

        pub func_flush_chunk: Option<FlushChunkFn>,

        // Recommended chunk size tracking
        pub has_rem_chunk_size: bool,
        pub rem_chunk_size: u64,
        pub rem_chunk_speed: f64,

        // Per-measurement accumulators
        pub processed_blocks: i64,
        pub acc_delay_ns: u64,
        pub bpd1: i64,
        pub bpd2: i64,
        pub t1: Instant,
    }

    impl Flow {
        /// Initialize the flow controller.
        ///
        /// `max_process_rate` is in KB/s. If <= 0, no rate limiting.
        pub fn new(
            block_size: i32,
            total_size: u64,
            max_process_rate: i64,
            cb: ProgressCb,
            indent: u32,
            func_flush_chunk: Option<FlushChunkFn>,
        ) -> Self {
            assert!(block_size > 0);
            assert!(block_size as usize % SECTOR_SIZE == 0);

            Flow {
                total_size,
                total_processed: 0,
                cb,
                indent,
                block_size,
                blocks_per_delay: 1,
                delay_ns: 1_000_000_000, // 1 second
                step: 1,
                max_process_rate: if max_process_rate <= 0 {
                    f64::MAX
                } else {
                    max_process_rate as f64 * 1024.0
                },
                measured_blocks: 0,
                measured_time_ns: 0,
                state: FlowState::Inc,
                erase: 0,
                func_flush_chunk,
                has_rem_chunk_size: false,
                rem_chunk_size: 0,
                rem_chunk_speed: 0.0,
                processed_blocks: 0,
                acc_delay_ns: 0,
                bpd1: 0,
                bpd2: 0,
                t1: Instant::now(),
            }
        }

        /// Update total_size to total_processed + size.
        #[inline]
        pub fn inc_total_size(&mut self, size: u64) {
            self.total_size = self.total_processed + size;
        }

        /// Set indentation level.
        #[inline]
        pub fn set_indent(&mut self, indent: u32) {
            self.indent = indent;
        }

        /// Get remaining chunk size based on blocks_per_delay.
        pub fn get_rem_chunk_size(&self) -> u64 {
            let rem_blocks = self.blocks_per_delay - self.processed_blocks;
            assert!(rem_blocks > 0);
            let rem_size = rem_blocks as u64 * self.block_size as u64;

            if self.has_rem_chunk_size && rem_size >= self.rem_chunk_size {
                self.rem_chunk_size
            } else {
                rem_size
            }
        }

        /// Clear progress display by erasing previously printed characters.
        pub fn clear_progress(&mut self) {
            if self.erase <= 0 {
                if self.indent > 0 {
                    (self.cb)(self.indent, "\x08");
                }
                self.erase = 0;
                return;
            }

            let n = self.erase as usize;
            let mut buf = String::with_capacity(n * 3);
            for _ in 0..n {
                buf.push('\x08');
            }
            for _ in 0..n {
                buf.push(' ');
            }
            for _ in 0..n {
                buf.push('\x08');
            }
            (self.cb)(self.indent, &buf);
            self.erase = 0;
        }

        fn has_enough_measurements(&self) -> bool {
            self.measured_time_ns > self.delay_ns
        }

        fn get_avg_speed(&self) -> f64 {
            self.get_avg_speed_given_time(self.measured_time_ns)
        }

        fn get_avg_speed_given_time(&self, total_time_ns: u64) -> f64 {
            (self.measured_blocks as f64 * self.block_size as f64 * 1_000_000_000.0)
                / total_time_ns as f64
        }

        fn report_progress(&mut self, inst_speed: f64) {
            let mut speed = inst_speed;
            let (val, unit) = libutils::adjust_unit(speed);
            speed = val;

            if self.total_size < self.total_processed {
                self.total_size = self.total_processed;
            }

            let percent =
                self.total_processed as f64 * 100.0 / self.total_size as f64;
            let mut buf = format!("{:.2}% -- {:.2} {}/s", percent, speed, unit);

            if self.has_enough_measurements() {
                let remaining_bytes =
                    self.total_size.saturating_sub(self.total_processed) as f64;
                let eta_secs = remaining_bytes / self.get_avg_speed();
                buf.push_str(&format_eta(eta_secs));
            }

            self.clear_progress();
            let len = buf.len();
            (self.cb)(self.indent, &buf);
            self.erase = len as i32;
        }

        fn update_rem_chunk_size(&mut self, inst_speed: f64) {
            if self.rem_chunk_size != 0 && inst_speed < self.rem_chunk_speed {
                return;
            }
            self.rem_chunk_size =
                self.blocks_per_delay as u64 * self.block_size as u64;
            self.rem_chunk_speed = inst_speed;
        }

        fn is_rate_above(&self, delay_ns: u64, inst_speed: f64) -> bool {
            delay_ns > self.delay_ns || inst_speed > self.max_process_rate
        }

        fn is_rate_below(&self, delay_ns: u64, inst_speed: f64) -> bool {
            delay_ns <= self.delay_ns && inst_speed < self.max_process_rate
        }

        fn move_to_inc_at_start(&mut self) {
            self.step = 1;
            self.state = FlowState::Inc;
        }

        fn move_to_steady(&mut self) {
            self.state = FlowState::Steady;
        }

        fn move_to_search(&mut self, bpd1: i64, bpd2: i64) {
            assert!(bpd1 > 0);
            assert!(bpd2 >= bpd1);

            self.blocks_per_delay = (bpd1 + bpd2) / 2;
            if bpd2 - bpd1 <= 3 {
                self.move_to_steady();
                return;
            }

            self.bpd1 = bpd1;
            self.bpd2 = bpd2;
            self.state = FlowState::Search;
        }

        fn inc_step(&mut self) {
            self.blocks_per_delay += self.step;
            self.step *= 2;
        }

        fn dec_step(&mut self) {
            if self.blocks_per_delay - self.step > 0 {
                self.blocks_per_delay -= self.step;
                self.step *= 2;
            } else {
                let bpd = self.blocks_per_delay + self.step / 2;
                self.move_to_search(1, bpd);
            }
        }

        fn move_to_inc(&mut self) {
            self.move_to_inc_at_start();
            self.inc_step();
        }

        fn move_to_dec(&mut self) {
            self.step = 1;
            self.state = FlowState::Dec;
            self.dec_step();
        }

        /// Start a measurement interval (records timestamp).
        pub fn start_measurement(&mut self) {
            let speed = self.blocks_per_delay as f64
                * self.block_size as f64
                * 1_000_000_000.0
                / self.delay_ns as f64;
            self.report_progress(speed);
            self.t1 = Instant::now();
        }

        /// Called after processing `processed` bytes. Adjusts throughput.
        /// Returns 0 on success, -1 on flush error.
        pub fn measure(&mut self, fd: i32, processed: i64) -> i32 {
            let blocks = processed / self.block_size as i64;
            assert_eq!(processed % self.block_size as i64, 0);
            self.processed_blocks += blocks;
            self.total_processed += processed as u64;

            if self.processed_blocks < self.blocks_per_delay {
                return 0;
            }
            assert_eq!(self.processed_blocks, self.blocks_per_delay);

            // Flush chunk if callback set
            if let Some(flush) = self.func_flush_chunk {
                if flush(fd) < 0 {
                    return -1;
                }
            }

            let t2 = Instant::now();
            let elapsed_ns = t2.duration_since(self.t1).as_nanos() as u64;
            let mut delay_ns = elapsed_ns + self.acc_delay_ns;
            let bytes_g =
                self.blocks_per_delay as f64 * self.block_size as f64 * 1_000_000_000.0;
            let mut inst_speed = bytes_g / delay_ns as f64;

            if !self.has_rem_chunk_size {
                self.update_rem_chunk_size(inst_speed);
            }

            // Rate limiting: if too fast, sleep to slow down.
            if delay_ns < self.delay_ns && inst_speed > self.max_process_rate {
                let wait_ns = ((bytes_g - delay_ns as f64 * self.max_process_rate)
                    / self.max_process_rate)
                    .round();

                let final_wait = if wait_ns >= 0.0 {
                    let w = wait_ns as u64;
                    if delay_ns + w < self.delay_ns {
                        self.delay_ns - delay_ns
                    } else {
                        w
                    }
                } else {
                    0
                };

                if final_wait > 0 {
                    std::thread::sleep(std::time::Duration::from_nanos(final_wait));
                    delay_ns += final_wait;
                    inst_speed = bytes_g / delay_ns as f64;
                }
            }

            // Update cumulative measurements
            self.measured_blocks += self.processed_blocks as u64;
            self.measured_time_ns += delay_ns;

            // State machine transitions
            match self.state {
                FlowState::Inc => {
                    if self.is_rate_above(delay_ns, inst_speed) {
                        if !self.has_rem_chunk_size {
                            assert!(self.rem_chunk_size != 0);
                            self.has_rem_chunk_size = true;
                        }
                        let bpd1 = self.blocks_per_delay - self.step / 2;
                        let bpd2 = self.blocks_per_delay;
                        self.move_to_search(bpd1, bpd2);
                    } else if self.is_rate_below(delay_ns, inst_speed) {
                        self.inc_step();
                    } else {
                        self.move_to_steady();
                    }
                }
                FlowState::Dec => {
                    if self.is_rate_above(delay_ns, inst_speed) {
                        self.dec_step();
                    } else if self.is_rate_below(delay_ns, inst_speed) {
                        let bpd1 = self.blocks_per_delay;
                        let bpd2 = self.blocks_per_delay + self.step / 2;
                        self.move_to_search(bpd1, bpd2);
                    } else {
                        self.move_to_steady();
                    }
                }
                FlowState::Search => {
                    if self.bpd2 - self.bpd1 <= 3 {
                        self.move_to_steady();
                    } else if self.is_rate_above(delay_ns, inst_speed) {
                        self.bpd2 = self.blocks_per_delay;
                        self.blocks_per_delay = (self.bpd1 + self.bpd2) / 2;
                    } else if self.is_rate_below(delay_ns, inst_speed) {
                        self.bpd1 = self.blocks_per_delay;
                        self.blocks_per_delay = (self.bpd1 + self.bpd2) / 2;
                    } else {
                        self.move_to_steady();
                    }
                }
                FlowState::Steady => {
                    if !self.has_rem_chunk_size {
                        assert!(self.rem_chunk_size != 0);
                        self.has_rem_chunk_size = true;
                    } else if delay_ns <= self.delay_ns {
                        if inst_speed < self.max_process_rate {
                            self.move_to_inc();
                        } else if inst_speed > self.max_process_rate {
                            self.move_to_dec();
                        }
                    } else if self.blocks_per_delay > 1 {
                        self.move_to_dec();
                    }
                }
            }

            self.report_progress(inst_speed);

            // Reset per-interval accumulators
            self.processed_blocks = 0;
            self.acc_delay_ns = 0;
            self.t1 = Instant::now();
            0
        }

        /// End a measurement (flush remaining, clear progress).
        /// Returns 0 on success, -1 on error.
        pub fn end_measurement(&mut self, fd: i32) -> i32 {
            let mut ret = 0i32;

            if self.processed_blocks > 0 {
                if let Some(flush) = self.func_flush_chunk {
                    if flush(fd) < 0 {
                        ret = -1;
                    }
                }

                if ret == 0 {
                    let t2 = Instant::now();
                    let elapsed_ns = t2.duration_since(self.t1).as_nanos() as u64;
                    self.acc_delay_ns += elapsed_ns;
                }
            }

            self.clear_progress();
            ret
        }

        /// Print measured average speed.
        pub fn print_measured_speed(
            &self,
            start: Instant,
            end: Instant,
            speed_type: &str,
        ) {
            if self.has_enough_measurements() {
                let speed = self.get_avg_speed();
                let (val, unit) = libutils::adjust_unit(speed);
                println!("Average {} speed: {:.2} {}/s", speed_type, val, unit);
            } else {
                let total_time_ms = end.duration_since(start).as_millis() as i64;
                if total_time_ms > 0 {
                    let speed = self
                        .get_avg_speed_given_time(total_time_ms as u64 * 1_000_000);
                    let (val, unit) = libutils::adjust_unit(speed);
                    println!(
                        "Average {} speed: {:.2} {}/s",
                        speed_type, val, unit
                    );
                } else {
                    let first = speed_type
                        .chars()
                        .next()
                        .unwrap_or(' ')
                        .to_uppercase()
                        .to_string();
                    println!(
                        "{}{} speed not available",
                        first,
                        &speed_type[1..]
                    );
                }
            }
        }
    }

    /// Format an ETA in seconds as " -- H:MM:SS" or " -- Ns".
    fn format_eta(mut sec: f64) -> String {
        let mut result = String::from(" -- ");

        let has_h = sec >= 3600.0;
        if has_h {
            let h = (sec / 3600.0).floor();
            result.push_str(&format!("{}:", h as i32));
            sec -= h * 3600.0;
        }

        let has_m = has_h || sec >= 60.0;
        if has_m {
            let m = (sec / 60.0).floor();
            if has_h {
                result.push_str(&format!("{:02}:", m as i32));
            } else {
                result.push_str(&format!("{}:", m as i32));
            }
            sec -= m * 60.0;
        }

        if has_m {
            result.push_str(&format!("{:02}", sec.round() as i32));
        } else {
            result.push_str(&format!("{}s", sec.round() as i32));
        }

        result
    }

    /// Dynamic buffer with 2MB backup.
    ///
    /// Tries to allocate requested size; falls back to smaller sizes
    /// or the built-in 2MB backup buffer.
    pub struct DynamicBuffer {
        buf: Vec<u8>,
        len: usize,
        max_buf: bool,
        backup_buf: Vec<u8>,
    }

    const BACKUP_BUF_SIZE: usize = 1 << 21; // 2MB

    impl DynamicBuffer {
        pub fn new() -> Self {
            let backup = vec![0u8; BACKUP_BUF_SIZE];
            DynamicBuffer {
                buf: Vec::new(),
                len: BACKUP_BUF_SIZE,
                max_buf: false,
                backup_buf: backup,
            }
        }

        /// Get a buffer of at least `size` bytes. May return smaller.
        /// Never returns an empty buffer.
        pub fn get_buf(&mut self, size: usize) -> &mut [u8] {
            // If enough buffer or already at max, return current
            if size <= self.len || self.max_buf {
                if self.buf.is_empty() {
                    return &mut self.backup_buf[..self.len];
                }
                return &mut self.buf[..self.len];
            }

            // Try to allocate progressively smaller buffers
            let mut try_size = size;
            while try_size > BACKUP_BUF_SIZE {
                let mut new_buf = Vec::new();
                if new_buf.try_reserve_exact(try_size).is_ok() {
                    new_buf.resize(try_size, 0);
                    self.buf = new_buf;
                    self.len = try_size;
                    return &mut self.buf[..self.len];
                }
                self.max_buf = true;
                try_size /= 2;
            }

            // Fall back to backup buffer
            self.buf = Vec::new();
            self.len = BACKUP_BUF_SIZE;
            &mut self.backup_buf[..self.len]
        }

        /// Current buffer length.
        #[inline]
        pub fn get_len(&self) -> usize {
            self.len
        }

        /// Free the dynamically allocated buffer, keeping the backup.
        /// After calling this, `get_len()` returns 0 and `get_buf()` will
        /// return the backup buffer. Matches C `dbuf_free()` semantics.
        pub fn free(&mut self) {
            self.buf = Vec::new();
            self.len = 0;
            self.max_buf = true;
        }
    }

    impl Default for DynamicBuffer {
        fn default() -> Self {
            Self::new()
        }
    }
}

pub mod fs_utils {
    //! Filesystem utilities for .h2w test files.

    use std::fs;
    use std::path::PathBuf;

    pub const GIGABYTES: u64 = 1024 * 1024 * 1024;

    /// Check if a filename matches /^[0-9]+\.h2w$/
    pub fn is_my_file(filename: &str) -> bool {
        let bytes = filename.as_bytes();
        if bytes.is_empty() || !bytes[0].is_ascii_digit() {
            return false;
        }

        let mut i = 0;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }

        // Must end with ".h2w"
        &bytes[i..] == b".h2w"
    }

    /// Extract the file number from a .h2w filename (1-based in filename, 0-based returned).
    pub fn number_from_filename(filename: &str) -> i64 {
        assert!(is_my_file(filename));
        let dot_pos = filename.find('.').unwrap();
        let num: i64 = filename[..dot_pos].parse().unwrap();
        num - 1
    }

    /// Create a full path like "PATH/(num+1).h2w".
    pub fn full_fn_from_number(path: &str, num: i64) -> (PathBuf, String) {
        let filename = format!("{}.h2w", num + 1);
        let full_path = PathBuf::from(path).join(&filename);
        (full_path, filename)
    }

    /// List all .h2w files in `path` with numbers in [start_at, end_at].
    /// Returns sorted vector of 0-based file numbers.
    pub fn ls_my_files(path: &str, start_at: i64, end_at: i64) -> Vec<i64> {
        loop {
            match try_ls_my_files(path, start_at, end_at) {
                Some(v) => return v,
                None => continue, // Retry if directory changed during scan
            }
        }
    }

    fn try_ls_my_files(path: &str, start_at: i64, end_at: i64) -> Option<Vec<i64>> {
        let dir = match fs::read_dir(path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Can't open path {}: {}", path, e);
                std::process::exit(1);
            }
        };

        let mut result = Vec::new();
        for entry in dir.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if is_my_file(name) {
                    let num = number_from_filename(name);
                    if num >= start_at && num <= end_at {
                        result.push(num);
                    }
                }
            }
        }

        result.sort();
        Some(result)
    }

    /// Get filesystem block size (f_frsize from statvfs).
    #[cfg(unix)]
    pub fn get_block_size(path: &str) -> i32 {
        use std::ffi::CString;
        let c_path = CString::new(path).expect("Invalid path");
        unsafe {
            let mut stat: libc::statvfs = std::mem::zeroed();
            let ret = libc::statvfs(c_path.as_ptr(), &mut stat);
            assert_eq!(ret, 0, "statvfs failed for {}", path);
            stat.f_frsize as i32
        }
    }

    /// Change working directory to path, attempt chroot.
    #[cfg(unix)]
    pub fn adjust_dev_path(dev_path: &str) -> String {
        use std::ffi::CString;
        let c_path = CString::new(dev_path).expect("Invalid path");

        unsafe {
            if libc::chdir(c_path.as_ptr()) != 0 {
                let err = std::io::Error::last_os_error();
                eprintln!(
                    "Can't change working directory to {}: {}",
                    dev_path, err
                );
                std::process::exit(1);
            }
        }

        let dot = CString::new(".").unwrap();
        unsafe {
            if libc::chroot(dot.as_ptr()) != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EPERM) {
                    eprintln!(
                        "Can't change root directory to {}: {}",
                        dev_path, err
                    );
                    std::process::exit(1);
                }
                // EPERM is fine - just means we're not root
            } else {
                let root = CString::new("/").unwrap();
                let ret = libc::chdir(root.as_ptr());
                assert_eq!(ret, 0);
            }
        }

        ".".to_string()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_is_my_file() {
            assert!(is_my_file("1.h2w"));
            assert!(is_my_file("123.h2w"));
            assert!(is_my_file("9999.h2w"));
            assert!(!is_my_file(".h2w"));
            assert!(!is_my_file("abc.h2w"));
            assert!(!is_my_file("1.txt"));
            assert!(!is_my_file("1.h2w.bak"));
            assert!(!is_my_file(""));
        }

        #[test]
        fn test_number_from_filename() {
            assert_eq!(number_from_filename("1.h2w"), 0);
            assert_eq!(number_from_filename("2.h2w"), 1);
            assert_eq!(number_from_filename("100.h2w"), 99);
        }

        #[test]
        fn test_full_fn_from_number() {
            let (path, name) = full_fn_from_number("/mnt/usb", 0);
            assert_eq!(path, PathBuf::from("/mnt/usb/1.h2w"));
            assert_eq!(name, "1.h2w");

            let (path, name) = full_fn_from_number(".", 9);
            assert_eq!(path, PathBuf::from("./10.h2w"));
            assert_eq!(name, "10.h2w");
        }
    }
}

pub mod devs {
    //! Device abstraction layer.
    //!
    //! Provides a trait-based device model with implementations for:
    //! - FileDevice: emulated device for testing
    //! - BlockDevice: real block device (Linux only)
    //! - PerfDevice: timing wrapper
    //! - SafeDevice: saves blocks before overwriting for recovery

    use std::io;
    use std::time::Instant;

    use crate::libutils::{self, SECTOR_ORDER};

    /// Classification of fake/fraudulent device types.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FakeType {
        Good,
        Bad,
        Limbo,
        Wraparound,
        Chain,
    }

    impl FakeType {
        pub fn to_name(self) -> &'static str {
            match self {
                FakeType::Good => "good",
                FakeType::Bad => "bad",
                FakeType::Limbo => "limbo",
                FakeType::Wraparound => "wraparound",
                FakeType::Chain => "chain",
            }
        }
    }

    /// Validate device parameters.
    pub fn dev_param_valid(
        real_size_byte: u64,
        announced_size_byte: u64,
        wrap: i32,
        block_order: u32,
    ) -> bool {
        if real_size_byte > announced_size_byte
            || wrap < 0
            || wrap >= 64
            || block_order < SECTOR_ORDER
            || block_order > 20
        {
            return false;
        }

        let block_size = 1u64 << block_order;
        if real_size_byte % block_size != 0 || announced_size_byte % block_size != 0 {
            return false;
        }

        if real_size_byte == announced_size_byte {
            let two_wrap = 1u64 << wrap;
            return announced_size_byte <= two_wrap;
        }

        true
    }

    /// Determine the fake type from device parameters.
    pub fn dev_param_to_type(
        real_size_byte: u64,
        announced_size_byte: u64,
        wrap: i32,
        block_order: u32,
    ) -> FakeType {
        assert!(dev_param_valid(
            real_size_byte,
            announced_size_byte,
            wrap,
            block_order
        ));

        if real_size_byte == announced_size_byte {
            return FakeType::Good;
        }

        if real_size_byte == 0 {
            return FakeType::Bad;
        }

        let two_wrap = 1u64 << wrap;
        if two_wrap <= real_size_byte {
            FakeType::Wraparound
        } else if two_wrap < announced_size_byte {
            FakeType::Chain
        } else {
            FakeType::Limbo
        }
    }

    /// USB reset strategy.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ResetType {
        ManualUsb,
        Usb,
        None,
    }

    /// Abstract device trait.
    pub trait Device {
        /// Total size in bytes.
        fn size_byte(&self) -> u64;
        /// Block order (log2 of block size).
        fn block_order(&self) -> u32;
        /// Block size in bytes.
        fn block_size(&self) -> usize {
            1 << self.block_order()
        }
        /// Device filename.
        fn get_filename(&self) -> &str;
        /// Read blocks [first_pos, last_pos] into buf. Positions in block units.
        fn read_blocks(
            &mut self,
            buf: &mut [u8],
            first_pos: u64,
            last_pos: u64,
        ) -> io::Result<()>;
        /// Write blocks [first_pos, last_pos] from buf. Positions in block units.
        fn write_blocks(
            &mut self,
            buf: &[u8],
            first_pos: u64,
            last_pos: u64,
        ) -> io::Result<()>;
        /// Reset the device.
        fn reset(&mut self) -> io::Result<()>;
    }

    // ========================================================================
    // FileDevice: emulated device for testing
    // ========================================================================

    /// Emulated device backed by a file, for testing fake drive behavior.
    pub struct FileDevice {
        filename: String,
        fd: std::fs::File,
        real_size_byte: u64,
        announced_size_byte: u64,
        block_order: u32,
        address_mask: u64,
        cache_mask: u64,
        cache_entries: Vec<u64>,
        cache_blocks: Vec<u8>,
        keep_file: bool,
    }

    impl FileDevice {
        /// Create a new file device.
        ///
        /// - `real_size_byte`: actual storage capacity
        /// - `fake_size_byte`: announced (possibly fraudulent) capacity
        /// - `wrap`: address wrap bit (modulo = 2^wrap)
        /// - `block_order`: log2 of block size
        /// - `cache_order`: log2 of cache size in blocks (0 = no cache)
        /// - `strict_cache`: if true, cache uses bitmap for exact tracking
        /// - `keep_file`: if true, don't delete file on drop
        pub fn new(
            filename: &str,
            real_size_byte: u64,
            fake_size_byte: u64,
            wrap: i32,
            block_order: u32,
            cache_order: i32,
            _strict_cache: bool,
            keep_file: bool,
        ) -> io::Result<Self> {
            use std::fs::OpenOptions;

            assert!(dev_param_valid(
                real_size_byte,
                fake_size_byte,
                wrap,
                block_order
            ));

            let fd = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(!keep_file)
                .open(filename)?;

            // Set file to real_size_byte
            fd.set_len(real_size_byte)?;

            let address_mask = if wrap > 0 {
                (1u64 << wrap) - 1
            } else {
                u64::MAX
            };

            let (cache_mask, cache_size) = if cache_order > 0 {
                let size = 1u64 << cache_order;
                ((size - 1), size as usize)
            } else {
                (0, 0)
            };

            let block_size = 1usize << block_order;
            let cache_blocks = vec![0u8; cache_size * block_size];
            let cache_entries = vec![u64::MAX; cache_size];

            Ok(FileDevice {
                filename: filename.to_string(),
                fd,
                real_size_byte,
                announced_size_byte: fake_size_byte,
                block_order,
                address_mask,
                cache_mask,
                cache_entries,
                cache_blocks,
                keep_file,
            })
        }
    }

    impl Device for FileDevice {
        fn size_byte(&self) -> u64 {
            self.announced_size_byte
        }

        fn block_order(&self) -> u32 {
            self.block_order
        }

        fn get_filename(&self) -> &str {
            &self.filename
        }

        fn read_blocks(
            &mut self,
            buf: &mut [u8],
            first_pos: u64,
            last_pos: u64,
        ) -> io::Result<()> {
            use std::io::{Read, Seek, SeekFrom};

            let block_size = self.block_size();
            let real_blocks = self.real_size_byte >> self.block_order;

            for pos in first_pos..=last_pos {
                let buf_offset = ((pos - first_pos) as usize) * block_size;
                let dest = &mut buf[buf_offset..buf_offset + block_size];

                // Apply address mask for wraparound
                let mapped_pos = pos & (self.address_mask >> self.block_order);

                if mapped_pos < real_blocks {
                    let byte_offset = mapped_pos << self.block_order;
                    self.fd.seek(SeekFrom::Start(byte_offset))?;
                    self.fd.read_exact(dest)?;
                } else if !self.cache_entries.is_empty() {
                    // Check cache
                    let cache_idx = (pos & self.cache_mask) as usize;
                    if cache_idx < self.cache_entries.len()
                        && self.cache_entries[cache_idx] == pos
                    {
                        let src_offset = cache_idx * block_size;
                        dest.copy_from_slice(
                            &self.cache_blocks[src_offset..src_offset + block_size],
                        );
                    } else {
                        dest.fill(0);
                    }
                } else {
                    dest.fill(0);
                }
            }
            Ok(())
        }

        fn write_blocks(
            &mut self,
            buf: &[u8],
            first_pos: u64,
            last_pos: u64,
        ) -> io::Result<()> {
            use std::io::{Seek, SeekFrom, Write};

            let block_size = self.block_size();
            let real_blocks = self.real_size_byte >> self.block_order;

            for pos in first_pos..=last_pos {
                let buf_offset = ((pos - first_pos) as usize) * block_size;
                let src = &buf[buf_offset..buf_offset + block_size];

                let mapped_pos = pos & (self.address_mask >> self.block_order);

                if mapped_pos < real_blocks {
                    let byte_offset = mapped_pos << self.block_order;
                    self.fd.seek(SeekFrom::Start(byte_offset))?;
                    self.fd.write_all(src)?;
                } else if !self.cache_entries.is_empty() {
                    let cache_idx = (pos & self.cache_mask) as usize;
                    if cache_idx < self.cache_entries.len() {
                        self.cache_entries[cache_idx] = pos;
                        let dst_offset = cache_idx * block_size;
                        self.cache_blocks[dst_offset..dst_offset + block_size]
                            .copy_from_slice(src);
                    }
                }
                // If beyond real size and no cache: data is discarded (limbo)
            }
            Ok(())
        }

        fn reset(&mut self) -> io::Result<()> {
            // File device: no-op reset
            Ok(())
        }
    }

    impl Drop for FileDevice {
        fn drop(&mut self) {
            if !self.keep_file {
                let _ = std::fs::remove_file(&self.filename);
            }
        }
    }

    // ========================================================================
    // BlockDevice: real block device (Linux)
    // ========================================================================

    // Linux ioctl constants for block devices
    #[cfg(target_os = "linux")]
    const BLKGETSIZE64: libc::c_ulong = 0x80081272;
    #[cfg(target_os = "linux")]
    const BLKSSZGET: libc::c_ulong = 0x1268;

    /// Real block device with O_DIRECT I/O.
    #[cfg(target_os = "linux")]
    pub struct BlockDevice {
        filename: String,
        fd: i32, // raw fd for O_DIRECT
        size_byte: u64,
        block_order: u32,
        reset_type: ResetType,
    }

    #[cfg(target_os = "linux")]
    impl BlockDevice {
        /// Open a block device.
        pub fn new(filename: &str, rt: ResetType) -> io::Result<Self> {
            use std::ffi::CString;

            let c_filename = CString::new(filename).unwrap();
            let fd = unsafe {
                libc::open(
                    c_filename.as_ptr(),
                    libc::O_RDWR | libc::O_DIRECT,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            // Get device size via BLKGETSIZE64
            let mut size: u64 = 0;
            let ret = unsafe {
                libc::ioctl(
                    fd,
                    BLKGETSIZE64,
                    &mut size as *mut u64,
                )
            };
            if ret < 0 {
                unsafe { libc::close(fd) };
                return Err(io::Error::last_os_error());
            }

            // Get logical sector size via BLKSSZGET
            let mut hw_sector: i32 = 0;
            let ret = unsafe {
                libc::ioctl(
                    fd,
                    BLKSSZGET,
                    &mut hw_sector as *mut i32,
                )
            };
            if ret < 0 {
                unsafe { libc::close(fd) };
                return Err(io::Error::last_os_error());
            }

            let block_order = libutils::ilog2(hw_sector as u64) as u32;

            Ok(BlockDevice {
                filename: filename.to_string(),
                fd,
                size_byte: size,
                block_order,
                reset_type: rt,
            })
        }

        fn read_all(fd: i32, buf: &mut [u8]) -> io::Result<()> {
            let mut done = 0usize;
            while done < buf.len() {
                let rc = unsafe {
                    libc::read(
                        fd,
                        buf[done..].as_mut_ptr() as *mut libc::c_void,
                        buf.len() - done,
                    )
                };
                if rc < 0 {
                    let err = io::Error::last_os_error();
                    match err.raw_os_error() {
                        Some(libc::EINTR) => continue,
                        Some(libc::EIO) | Some(libc::ENODATA) => {
                            buf[done..].fill(0);
                            return Ok(());
                        }
                        _ => return Err(err),
                    }
                }
                done += rc as usize;
            }
            Ok(())
        }

        fn write_all(fd: i32, buf: &[u8]) -> io::Result<()> {
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
                    return Err(io::Error::last_os_error());
                }
                done += rc as usize;
            }
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    impl Device for BlockDevice {
        fn size_byte(&self) -> u64 {
            self.size_byte
        }

        fn block_order(&self) -> u32 {
            self.block_order
        }

        fn get_filename(&self) -> &str {
            &self.filename
        }

        fn read_blocks(
            &mut self,
            buf: &mut [u8],
            first_pos: u64,
            last_pos: u64,
        ) -> io::Result<()> {
            let block_size = self.block_size();
            let byte_offset = first_pos << self.block_order;
            let total_bytes = ((last_pos - first_pos + 1) as usize) * block_size;

            let ret = unsafe {
                libc::lseek(self.fd, byte_offset as libc::off_t, libc::SEEK_SET)
            };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }

            Self::read_all(self.fd, &mut buf[..total_bytes])
        }

        fn write_blocks(
            &mut self,
            buf: &[u8],
            first_pos: u64,
            last_pos: u64,
        ) -> io::Result<()> {
            let block_size = self.block_size();
            let byte_offset = first_pos << self.block_order;
            let total_bytes = ((last_pos - first_pos + 1) as usize) * block_size;

            let ret = unsafe {
                libc::lseek(self.fd, byte_offset as libc::off_t, libc::SEEK_SET)
            };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }

            Self::write_all(self.fd, &buf[..total_bytes])?;

            // Sync and advise kernel to drop cache
            unsafe {
                libc::fsync(self.fd);
                libc::posix_fadvise(
                    self.fd,
                    byte_offset as libc::off_t,
                    total_bytes as libc::off_t,
                    libc::POSIX_FADV_DONTNEED,
                );
            }

            Ok(())
        }

        fn reset(&mut self) -> io::Result<()> {
            match self.reset_type {
                ResetType::None => Ok(()),
                ResetType::ManualUsb | ResetType::Usb => {
                    // USB reset requires udev interaction; placeholder
                    eprintln!("USB reset not yet implemented in Rust port");
                    Ok(())
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for BlockDevice {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    // ========================================================================
    // PerfDevice: timing wrapper
    // ========================================================================

    /// Performance measurement wrapper around any Device.
    pub struct PerfDevice {
        shadow_dev: Box<dyn Device>,
        pub read_count: u64,
        pub read_time_us: u64,
        pub write_count: u64,
        pub write_time_us: u64,
        pub reset_count: u64,
        pub reset_time_us: u64,
    }

    impl PerfDevice {
        pub fn new(dev: Box<dyn Device>) -> Self {
            PerfDevice {
                shadow_dev: dev,
                read_count: 0,
                read_time_us: 0,
                write_count: 0,
                write_time_us: 0,
                reset_count: 0,
                reset_time_us: 0,
            }
        }

        /// Get performance sample.
        pub fn sample(
            &self,
        ) -> (u64, u64, u64, u64, u64, u64) {
            (
                self.read_count,
                self.read_time_us,
                self.write_count,
                self.write_time_us,
                self.reset_count,
                self.reset_time_us,
            )
        }

        /// Detach and return the inner device.
        pub fn detach(self) -> Box<dyn Device> {
            self.shadow_dev
        }
    }

    impl Device for PerfDevice {
        fn size_byte(&self) -> u64 {
            self.shadow_dev.size_byte()
        }

        fn block_order(&self) -> u32 {
            self.shadow_dev.block_order()
        }

        fn get_filename(&self) -> &str {
            self.shadow_dev.get_filename()
        }

        fn read_blocks(
            &mut self,
            buf: &mut [u8],
            first_pos: u64,
            last_pos: u64,
        ) -> io::Result<()> {
            let start = Instant::now();
            let result = self.shadow_dev.read_blocks(buf, first_pos, last_pos);
            let elapsed = start.elapsed().as_micros() as u64;
            self.read_count += 1;
            self.read_time_us += elapsed;
            result
        }

        fn write_blocks(
            &mut self,
            buf: &[u8],
            first_pos: u64,
            last_pos: u64,
        ) -> io::Result<()> {
            let start = Instant::now();
            let result = self.shadow_dev.write_blocks(buf, first_pos, last_pos);
            let elapsed = start.elapsed().as_micros() as u64;
            self.write_count += 1;
            self.write_time_us += elapsed;
            result
        }

        fn reset(&mut self) -> io::Result<()> {
            let start = Instant::now();
            let result = self.shadow_dev.reset();
            let elapsed = start.elapsed().as_micros() as u64;
            self.reset_count += 1;
            self.reset_time_us += elapsed;
            result
        }
    }

    // ========================================================================
    // SafeDevice: saves blocks before overwriting
    // ========================================================================

    /// Safe device wrapper: saves blocks before overwriting for recovery.
    pub struct SafeDevice {
        shadow_dev: Box<dyn Device>,
        saved_blocks: Vec<u8>,
        sb_positions: Vec<u64>,
        sb_bitmap: Vec<u64>,
        sb_n: u64,
        sb_max: u64,
        use_bitmap: bool,
    }

    const BITMAP_BITS_PER_WORD: u64 = 64;

    impl SafeDevice {
        /// Create a safe device wrapper.
        ///
        /// `max_blocks`: maximum number of blocks to save
        /// `min_memory`: if true, don't allocate bitmap
        pub fn new(
            dev: Box<dyn Device>,
            max_blocks: u64,
            min_memory: bool,
        ) -> io::Result<Self> {
            let block_size = dev.block_size();
            let saved_blocks = vec![0u8; (max_blocks as usize) * block_size];
            let sb_positions = vec![u64::MAX; max_blocks as usize];

            let (sb_bitmap, use_bitmap) = if !min_memory {
                let total_blocks = dev.size_byte() >> dev.block_order();
                let bitmap_words =
                    ((total_blocks + BITMAP_BITS_PER_WORD - 1) / BITMAP_BITS_PER_WORD)
                        as usize;
                (vec![0u64; bitmap_words], true)
            } else {
                (Vec::new(), false)
            };

            Ok(SafeDevice {
                shadow_dev: dev,
                saved_blocks,
                sb_positions,
                sb_bitmap,
                sb_n: 0,
                sb_max: max_blocks,
                use_bitmap,
            })
        }

        fn is_block_saved(&self, pos: u64) -> bool {
            if self.use_bitmap {
                let word_idx = (pos / BITMAP_BITS_PER_WORD) as usize;
                let bit_idx = pos % BITMAP_BITS_PER_WORD;
                if word_idx < self.sb_bitmap.len() {
                    self.sb_bitmap[word_idx] & (1u64 << bit_idx) != 0
                } else {
                    false
                }
            } else {
                // Linear search
                for i in 0..self.sb_n as usize {
                    if self.sb_positions[i] == pos {
                        return true;
                    }
                }
                false
            }
        }

        fn mark_block_saved(&mut self, pos: u64) {
            if self.use_bitmap {
                let word_idx = (pos / BITMAP_BITS_PER_WORD) as usize;
                let bit_idx = pos % BITMAP_BITS_PER_WORD;
                if word_idx < self.sb_bitmap.len() {
                    self.sb_bitmap[word_idx] |= 1u64 << bit_idx;
                }
            }
        }

        fn save_block(&mut self, pos: u64) -> io::Result<()> {
            if self.is_block_saved(pos) {
                return Ok(());
            }

            assert!(
                self.sb_n < self.sb_max,
                "SafeDevice: exceeded max saved blocks"
            );

            let block_size = self.shadow_dev.block_size();
            let idx = self.sb_n as usize;
            let offset = idx * block_size;

            // Read the block from the real device
            self.shadow_dev.read_blocks(
                &mut self.saved_blocks[offset..offset + block_size],
                pos,
                pos,
            )?;

            self.sb_positions[idx] = pos;
            self.mark_block_saved(pos);
            self.sb_n += 1;

            Ok(())
        }

        /// Recover all saved blocks by writing them back.
        pub fn recover(&mut self, _very_last_pos: u64) -> io::Result<()> {
            let block_size = self.shadow_dev.block_size();
            for i in 0..self.sb_n as usize {
                let pos = self.sb_positions[i];
                let offset = i * block_size;
                let data = self.saved_blocks[offset..offset + block_size].to_vec();
                self.shadow_dev.write_blocks(&data, pos, pos)?;
            }
            Ok(())
        }

        /// Flush (clear) the saved blocks cache.
        pub fn flush(&mut self) {
            self.sb_n = 0;
            for entry in self.sb_positions.iter_mut() {
                *entry = u64::MAX;
            }
            if self.use_bitmap {
                for word in self.sb_bitmap.iter_mut() {
                    *word = 0;
                }
            }
        }

        /// Get the inner device.
        pub fn into_inner(self) -> Box<dyn Device> {
            self.shadow_dev
        }
    }

    impl Device for SafeDevice {
        fn size_byte(&self) -> u64 {
            self.shadow_dev.size_byte()
        }

        fn block_order(&self) -> u32 {
            self.shadow_dev.block_order()
        }

        fn get_filename(&self) -> &str {
            self.shadow_dev.get_filename()
        }

        fn read_blocks(
            &mut self,
            buf: &mut [u8],
            first_pos: u64,
            last_pos: u64,
        ) -> io::Result<()> {
            self.shadow_dev.read_blocks(buf, first_pos, last_pos)
        }

        fn write_blocks(
            &mut self,
            buf: &[u8],
            first_pos: u64,
            last_pos: u64,
        ) -> io::Result<()> {
            // Save all blocks before overwriting
            for pos in first_pos..=last_pos {
                self.save_block(pos)?;
            }
            self.shadow_dev.write_blocks(buf, first_pos, last_pos)
        }

        fn reset(&mut self) -> io::Result<()> {
            self.shadow_dev.reset()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_dev_param_valid() {
            assert!(dev_param_valid(1024, 1024, 10, 9));
            assert!(!dev_param_valid(2048, 1024, 10, 9)); // real > announced
            assert!(!dev_param_valid(1024, 1024, -1, 9)); // wrap < 0
            assert!(!dev_param_valid(1024, 1024, 64, 9)); // wrap >= 64
            assert!(!dev_param_valid(1024, 1024, 10, 8)); // block_order < 9
        }

        #[test]
        fn test_dev_param_to_type() {
            assert_eq!(dev_param_to_type(1024, 1024, 10, 9), FakeType::Good);
            assert_eq!(dev_param_to_type(0, 1024, 10, 9), FakeType::Bad);
        }

        #[test]
        fn test_fake_type_names() {
            assert_eq!(FakeType::Good.to_name(), "good");
            assert_eq!(FakeType::Wraparound.to_name(), "wraparound");
        }
    }
}

pub mod probe {
    //! Probing algorithm for detecting fake flash drive capacity.
    //!
    //! Implements three main phases:
    //! 1. find_cache_size: detect device cache boundary
    //! 2. find_wrap: detect address wraparound modulus
    //! 3. sampling_probe: pinpoint exact real/fake boundary

    use std::io;

    use crate::devs::Device;
    use crate::flow::DynamicBuffer;
    use crate::libutils::{self, BlockState, ProgressCb};

    pub const SAMPLING_MIN: u32 = 8;
    pub const SAMPLING_MAX: u32 = 1024;
    pub const MAX_CACHE_SIZE_BYTE: u64 = 1 << 30; // 1GB

    /// Internal state for probe read/write operations.
    struct ProbeState {
        cache_pos: u64,
        cache_size_block: u64,
        salt: u64,
        seqw_dbuf: DynamicBuffer,
    }

    impl ProbeState {
        fn new() -> Self {
            ProbeState {
                cache_pos: 0,
                cache_size_block: 0,
                salt: rand_salt(),
                seqw_dbuf: DynamicBuffer::new(),
            }
        }
    }

    /// Generate a pseudorandom salt from the current time.
    fn rand_salt() -> u64 {
        use std::time::SystemTime;
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(42)
    }

    /// Fill a single block in a buffer at the given position.
    fn write_block(
        dev: &mut dyn Device,
        buf: &mut [u8],
        pos: u64,
        salt: u64,
    ) -> io::Result<()> {
        let block_order = dev.block_order();
        let offset = pos << block_order;
        libutils::fill_buffer_with_block(buf, block_order, offset, salt);
        dev.write_blocks(buf, pos, pos)
    }

    /// Read and validate a single block.
    fn read_and_validate_block(
        dev: &mut dyn Device,
        buf: &mut [u8],
        pos: u64,
        salt: u64,
    ) -> io::Result<BlockState> {
        let block_order = dev.block_order();
        let expected_offset = pos << block_order;
        dev.read_blocks(buf, pos, pos)?;
        let (state, _found) =
            libutils::validate_buffer_with_block(buf, block_order, expected_offset, salt);
        Ok(state)
    }

    /// Write sequential blocks in a range.
    fn write_blocks_sequential(
        dev: &mut dyn Device,
        state: &mut ProbeState,
        first_pos: u64,
        last_pos: u64,
    ) -> io::Result<()> {
        let block_size = dev.block_size();
        let block_order = dev.block_order();
        let count = (last_pos - first_pos + 1) as usize;
        let total_bytes = count * block_size;

        let buf = state.seqw_dbuf.get_buf(total_bytes);
        let usable_blocks = buf.len() / block_size;

        let mut pos = first_pos;
        while pos <= last_pos {
            let batch = std::cmp::min(usable_blocks as u64, last_pos - pos + 1);
            for i in 0..batch {
                let p = pos + i;
                let offset = p << block_order;
                let buf_offset = (i as usize) * block_size;
                libutils::fill_buffer_with_block(
                    &mut buf[buf_offset..buf_offset + block_size],
                    block_order,
                    offset,
                    state.salt,
                );
            }
            dev.write_blocks(
                &buf[..(batch as usize) * block_size],
                pos,
                pos + batch - 1,
            )?;
            pos += batch;
        }
        Ok(())
    }

    /// Overwhelm the device cache by writing enough data.
    fn overwhelm_cache(
        dev: &mut dyn Device,
        state: &mut ProbeState,
    ) -> io::Result<()> {
        if state.cache_size_block == 0 {
            return Ok(());
        }
        let start = state.cache_pos;
        let end = start + state.cache_size_block - 1;
        write_blocks_sequential(dev, state, start, end)?;
        state.cache_pos += state.cache_size_block;
        Ok(())
    }

    /// Test a range of blocks probabilistically (sample n_samples random positions).
    fn probabilistic_test(
        dev: &mut dyn Device,
        first_pos: u64,
        last_pos: u64,
        state: &mut ProbeState,
        n_samples: u32,
    ) -> io::Result<bool> {
        let block_size = dev.block_size();
        let mut buf = vec![0u8; block_size];
        let range = last_pos - first_pos + 1;

        // Simple PRNG for sampling positions
        let mut rng = first_pos ^ (n_samples as u64);
        let mut found_bad = false;

        let actual_samples = std::cmp::min(n_samples as u64, range);
        for _ in 0..actual_samples {
            rng = libutils::next_random_number(rng);
            let pos = first_pos + (rng % range);
            let state_result = read_and_validate_block(dev, &mut buf, pos, state.salt)?;
            if state_result != BlockState::Good {
                found_bad = true;
                break;
            }
        }
        Ok(found_bad)
    }

    /// Find a bad block in the range (left_pos, right_pos) using n_samples.
    /// Returns (found_bad, new_right_pos).
    fn find_a_bad_block(
        dev: &mut dyn Device,
        n_samples: u32,
        left_pos: u64,
        right_pos: u64,
        state: &mut ProbeState,
    ) -> io::Result<(bool, u64)> {
        let block_size = dev.block_size();
        let mut buf = vec![0u8; block_size];
        let range = right_pos - left_pos;
        if range <= 1 {
            return Ok((false, right_pos));
        }

        let actual_samples = std::cmp::min(n_samples as u64, range - 1);

        // Generate sample positions
        let mut positions: Vec<u64> = Vec::with_capacity(actual_samples as usize);
        let mut rng = left_pos ^ right_pos ^ (n_samples as u64);
        for _ in 0..actual_samples {
            rng = libutils::next_random_number(rng);
            let pos = left_pos + 1 + (rng % (range - 1));
            positions.push(pos);
        }
        positions.sort();
        positions.dedup();

        // Write all sample positions
        for &pos in &positions {
            write_block(dev, &mut buf, pos, state.salt)?;
        }

        // Overwhelm cache
        overwhelm_cache(dev, state)?;

        // Read back and check
        let mut new_right = right_pos;
        let mut found = false;
        for &pos in &positions {
            let bs = read_and_validate_block(dev, &mut buf, pos, state.salt)?;
            if bs != BlockState::Good {
                if pos < new_right {
                    new_right = pos;
                }
                found = true;
            }
        }

        Ok((found, new_right))
    }

    /// Phase 1: Find the device cache size and first bad block boundary.
    fn find_cache_size(
        dev: &mut dyn Device,
        left_pos: u64,
        right_pos: &mut u64,
        state: &mut ProbeState,
        cb: ProgressCb,
        indent: u32,
    ) -> io::Result<()> {
        let block_order = dev.block_order();
        let max_write_blocks = MAX_CACHE_SIZE_BYTE >> block_order;
        let mut write_target: u64 = 1;

        cb(indent, "Finding cache size...\n");

        while write_target <= max_write_blocks {
            if write_target > *right_pos - left_pos {
                break;
            }

            let first_pos = *right_pos - write_target;
            let end_pos = *right_pos - 1;

            // Write the range
            write_blocks_sequential(dev, state, first_pos, end_pos)?;

            // Test probabilistically
            let found_bad = probabilistic_test(dev, first_pos, end_pos, state, 64)?;

            if found_bad {
                state.cache_size_block = end_pos - first_pos + 1;
                *right_pos = first_pos;
                cb(
                    indent,
                    &format!(
                        "Cache size: {} blocks\n",
                        state.cache_size_block
                    ),
                );
                return Ok(());
            }

            write_target *= 2;
        }

        // No bad blocks found — drive appears good
        cb(indent, "No cache effects detected\n");
        Ok(())
    }

    /// Phase 2: Detect address wrap point.
    fn find_wrap(
        dev: &mut dyn Device,
        left_pos: u64,
        right_pos: &mut u64,
        state: &mut ProbeState,
        cb: ProgressCb,
        indent: u32,
    ) -> io::Result<i32> {
        let block_size = dev.block_size();
        let mut buf = vec![0u8; block_size];

        cb(indent, "Finding wrap point...\n");

        // Use left_pos + 1 as reference block
        let ref_pos = left_pos + 1;
        write_block(dev, &mut buf, ref_pos, state.salt)?;
        overwhelm_cache(dev, state)?;

        // Check that reference block is good
        let ref_state = read_and_validate_block(dev, &mut buf, ref_pos, state.salt)?;
        if ref_state != BlockState::Good {
            cb(indent, "Reference block is bad; cannot detect wrap\n");
            return Ok(0);
        }

        // Test powers of 2: check if 2^m + ref_pos wraps to ref_pos
        let m_start = libutils::ceiling_log2(ref_pos + 1);
        let max_m = 64i32;

        for m in m_start..max_m {
            let test_pos = (1u64 << m).checked_add(ref_pos);
            let test_pos = match test_pos {
                Some(p) if p < *right_pos => p,
                _ => break,
            };

            // Read the test position (without writing to it)
            let test_state =
                read_and_validate_block(dev, &mut buf, test_pos, state.salt)?;

            if test_state == BlockState::Overwritten || test_state == BlockState::Good {
                // The data at test_pos matches ref_pos's data -> wrap detected
                cb(indent, &format!("Wrap detected at 2^{}\n", m));
                return Ok(m);
            }
        }

        cb(indent, "No wrap detected\n");
        Ok(0)
    }

    /// Phase 3: Sampling probe to find exact boundary.
    fn sampling_probe(
        dev: &mut dyn Device,
        mut left_pos: u64,
        right_pos: &mut u64,
        state: &mut ProbeState,
        cb: ProgressCb,
        indent: u32,
    ) -> io::Result<()> {
        cb(indent, "Sampling probe...\n");

        // Phase 1: exponential growth of sample size
        let mut n_samples = SAMPLING_MIN;

        loop {
            if *right_pos - left_pos <= (SAMPLING_MIN as u64) + 1 {
                break;
            }

            let (found, new_right) =
                find_a_bad_block(dev, n_samples, left_pos, *right_pos, state)?;

            if found {
                *right_pos = new_right;
                n_samples = SAMPLING_MIN;
                continue;
            }

            if n_samples >= SAMPLING_MAX {
                // Phase 2: binary narrowing
                left_pos = (left_pos + *right_pos) / 2;
                n_samples = SAMPLING_MIN;
                continue;
            }

            n_samples *= 2;
        }

        cb(
            indent,
            &format!(
                "Probe complete: boundary at block {}\n",
                *right_pos
            ),
        );
        Ok(())
    }

    /// Maximum blocks written during a probe (for safe device sizing).
    pub fn probe_max_written_blocks(dev: &dyn Device) -> u64 {
        let block_order = dev.block_order();
        let total_blocks = dev.size_byte() >> block_order;
        let n = if total_blocks > 0 {
            libutils::ilog2(total_blocks) as u64
        } else {
            1
        };

        let cache_part = (MAX_CACHE_SIZE_BYTE >> block_order) * 2 - 1;
        let wrap_part = 1u64;
        let sampling_part =
            (n + 3) * SAMPLING_MAX as u64 + (n.saturating_sub(1)) * SAMPLING_MIN as u64;

        cache_part + wrap_part + sampling_part
    }

    /// Report probed size.
    pub fn report_probed_size(
        indent: u32,
        cb: ProgressCb,
        prefix: &str,
        bytes: u64,
        block_order: u32,
    ) {
        let (val, unit) = libutils::adjust_unit(bytes as f64);
        let blocks = bytes >> block_order;
        cb(indent, &format!("{} {:.2} {} ({} blocks)\n", prefix, val, unit, blocks));
    }

    /// Report probed order.
    pub fn report_probed_order(indent: u32, cb: ProgressCb, prefix: &str, order: i32) {
        cb(
            indent,
            &format!("{} {} (2^{} bytes)\n", prefix, 1i64 << order, order),
        );
    }

    /// Report probed cache.
    pub fn report_probed_cache(
        indent: u32,
        cb: ProgressCb,
        prefix: &str,
        cache_size_block: u64,
        block_order: u32,
    ) {
        let bytes = cache_size_block << block_order;
        let (val, unit) = libutils::adjust_unit(bytes as f64);
        cb(
            indent,
            &format!(
                "{} {:.2} {} ({} blocks)\n",
                prefix, val, unit, cache_size_block
            ),
        );
    }

    /// Result of probing a device.
    #[derive(Debug, Clone)]
    pub struct ProbeResult {
        pub real_size_byte: u64,
        pub announced_size_byte: u64,
        pub wrap: i32,
        pub cache_size_block: u64,
        pub block_order: u32,
    }

    /// Main probe entry point: probes a device for fake capacity.
    ///
    /// Returns ProbeResult with the detected parameters.
    pub fn probe_device(
        dev: &mut dyn Device,
        cb: ProgressCb,
        show_progress: bool,
    ) -> io::Result<ProbeResult> {
        let block_order = dev.block_order();
        let block_size = dev.block_size() as u64;
        let announced_size = dev.size_byte();
        let total_blocks = announced_size / block_size;

        let active_cb: ProgressCb = if show_progress {
            cb
        } else {
            libutils::dummy_cb
        };

        let indent = 0u32;

        // Skip first 1MB (partition table area)
        let left_pos = (1024 * 1024 / block_size).saturating_sub(1);
        let mut right_pos = total_blocks;

        let mut state = ProbeState::new();

        // Phase 1: Find cache size
        find_cache_size(dev, left_pos, &mut right_pos, &mut state, active_cb, indent)?;

        // Phase 2: Find wrap
        let wrap =
            find_wrap(dev, left_pos, &mut right_pos, &mut state, active_cb, indent)?;

        // Phase 3: Sampling probe
        sampling_probe(dev, left_pos, &mut right_pos, &mut state, active_cb, indent)?;

        let real_size_byte = right_pos * block_size;

        Ok(ProbeResult {
            real_size_byte,
            announced_size_byte: announced_size,
            wrap,
            cache_size_block: state.cache_size_block,
            block_order,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_constants() {
            assert_eq!(SAMPLING_MIN, 8);
            assert_eq!(SAMPLING_MAX, 1024);
            assert_eq!(MAX_CACHE_SIZE_BYTE, 1 << 30);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert_eq!(F3_STR_VERSION, "9.0");
    }

    #[test]
    fn test_cross_module_compat() {
        // Verify that fill_buffer (f3write style) and fill_buffer_with_block
        // produce different output for the same offset (because they seed differently)
        let offset = 512u64;
        let salt = 0x12345678u64;

        let mut buf_block = vec![0u8; 512];
        libutils::fill_buffer_with_block(&mut buf_block, 9, offset, salt);

        let mut buf_write = vec![0u8; 512];
        libutils::fill_buffer(&mut buf_write, 512, offset);

        // First 8 bytes should be the same (both store the offset)
        assert_eq!(&buf_block[..8], &buf_write[..8]);

        // But subsequent bytes differ because seeding is different:
        // fill_buffer_with_block uses offset^salt as seed
        // fill_buffer uses sector[i-1] (previous output) as input
        assert_ne!(&buf_block[8..16], &buf_write[8..16]);
    }
}
