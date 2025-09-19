use clap::Parser;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Instant;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::arch::x86_64::*;

const MAX_CHALLENGE_LEN: usize = 96;
// 超大批处理 - 专为高难度优化
const ULTRA_BATCH_SIZE: usize = 1024 * 1024;  // 1M批处理，减少10倍同步
const CACHE_LINE_SIZE: usize = 64;

/// 命令行参数 - 添加高难度专用选项
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 交易ID
    #[arg(long)]
    txid: String,

    /// 输出索引
    #[arg(long)]
    vout: u32,

    /// 前导零位阈值
    #[arg(long, short)]
    threshold: Option<u32>,

    /// 持续模式
    #[arg(long, action)]
    stream: bool,

    /// 起始 nonce
    #[arg(long, default_value_t = 0)]
    start: u64,

    /// 搜索数量
    #[arg(long, default_value_t = 1000_000_000)]
    count: u64,

    /// 批处理大小 - 专为高难度优化
    #[arg(long, default_value_t = 1000_000_000)]
    batch: u64,

    /// 基线难度
    #[arg(long, default_value_t = 0)]
    baseline: u32,

    /// 线程数
    #[arg(long, default_value_t = 0)]
    threads: usize,

    /// 启用超级优化模式 (专为10+零优化)
    #[arg(long, action, default_value_t = true)]
    ultra_mode: bool,

    /// 自适应批处理 (根据难度动态调整)
    #[arg(long, action, default_value_t = true)]
    adaptive_batch: bool,

    /// 输出文件
    #[arg(long, short)]
    output: Option<String>,
    /// 内部并行块大小
    #[arg(long, default_value_t = 65536)]
    chunk_size: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PowResult {
    nonce: u64,
    hash_hex: String,
    leading_zero_bits: u32,
}

/// 高难度专用统计 - 追踪不同难度级别的性能
#[derive(Debug)]
struct HighDifficultyStats {
    total_hashes: AtomicU64,
    high_difficulty_hashes: AtomicU64,  // 10+零的专用计数
    best_found: AtomicU32,
    start_time: Instant,
    early_exit_enabled: AtomicBool,     // 智能早退机制
}

impl HighDifficultyStats {
    fn new() -> Self {
        Self {
            total_hashes: AtomicU64::new(0),
            high_difficulty_hashes: AtomicU64::new(0),
            best_found: AtomicU32::new(0),
            start_time: Instant::now(),
            early_exit_enabled: AtomicBool::new(false),
        }
    }

    fn add_hashes(&self, count: u64, is_high_difficulty: bool) {
        self.total_hashes.fetch_add(count, Ordering::Relaxed);
        if is_high_difficulty {
            self.high_difficulty_hashes.fetch_add(count, Ordering::Relaxed);
        }
    }

    fn update_best(&self, new_best: u32) {
        self.best_found.store(new_best, Ordering::Release);
        
        // 高难度时启用早退机制
        if new_best >= 10 {
            self.early_exit_enabled.store(true, Ordering::Release);
        }
    }

    fn calculate_adaptive_batch_size(&self) -> usize {
        let current_best = self.best_found.load(Ordering::Acquire);
        let base_size = ULTRA_BATCH_SIZE;
        
        // 根据当前最佳难度动态调整批处理大小
        match current_best {
            0..=7 => base_size,                    // 低难度：标准批处理
            8..=10 => base_size * 2,              // 中难度：2倍批处理
            11..=15 => base_size * 4,             // 高难度：4倍批处理
            16..=20 => base_size * 8,             // 极高难度：8倍批处理
            _ => base_size * 16,                  // 超高难度：16倍批处理
        }
    }

    fn get_hashrate_mhs(&self) -> f64 {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let total = self.total_hashes.load(Ordering::Relaxed);
        if elapsed > 0.0 {
            (total as f64) / (elapsed * 1_000_000.0)
        } else {
            0.0
        }
    }

    fn get_high_difficulty_ratio(&self) -> f64 {
        let total = self.total_hashes.load(Ordering::Relaxed);
        let high_diff = self.high_difficulty_hashes.load(Ordering::Relaxed);
        if total > 0 {
            (high_diff as f64) / (total as f64)
        } else {
            0.0
        }
    }
}

static GLOBAL_STATS: OnceLock<HighDifficultyStats> = OnceLock::new();

fn get_global_stats() -> &'static HighDifficultyStats {
    GLOBAL_STATS.get_or_init(|| HighDifficultyStats::new())
}

/// 专为高难度优化的前导零计算 - 早期快速过滤
#[inline(always)]
fn count_leading_zeros_high_difficulty_optimized(hash: &[u8; 32]) -> u32 {
    // 快速检查：如果前4字节不全为零，直接返回较小值
    let first_u32 = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
    if first_u32 != 0 {
        return first_u32.leading_zeros();
    }
    
    // 前4字节全零，继续检查剩余部分
    let hash_u64 = unsafe {
        std::slice::from_raw_parts(hash.as_ptr() as *const u64, 4)
    };
    
    let mut zero_bits = 0u32;
    for &quad in hash_u64 {
        if quad == 0 {
            zero_bits += 64;
        } else {
            zero_bits += quad.to_be().leading_zeros();
            break;
        }
    }
    
    zero_bits
}

/// 高难度专用SIMD优化 - AVX2 + 早期过滤
#[inline(always)]
fn count_leading_zeros_high_diff_simd(hash: &[u8; 32]) -> u32 {
    #[cfg(target_arch = "x86_64")]
    // 优先使用 AVX-512，它在支持的硬件上性能最佳。
    // AVX512BW (Byte/Word) 提供了我们需要的 epi8 比较指令。
    // AVX512VL 允许这些指令在 256 位向量上操作。
    if is_x86_feature_detected!("avx512bw") && is_x86_feature_detected!("avx512vl") {
        unsafe {
            return count_leading_zeros_avx512(hash);
        }
    }
    #[cfg(target_arch = "x86_64")]
    if is_x86_feature_detected!("avx2") {
        unsafe {
            return count_leading_zeros_avx2_high_diff(hash);
        }
    }
    
    count_leading_zeros_high_difficulty_optimized(hash)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn count_leading_zeros_avx2_high_diff(hash: &[u8; 32]) -> u32 {
    // 使用AVX2快速检查整个32字节
    let data_ptr = hash.as_ptr() as *const __m128i;
    let first_half = _mm_loadu_si128(data_ptr);
    let second_half = _mm_loadu_si128(data_ptr.add(1));
    let zero_vec = _mm_setzero_si128();
    
    // 比较两个128位向量是否为零
    let cmp1 = _mm_cmpeq_epi8(first_half, zero_vec);
    let cmp2 = _mm_cmpeq_epi8(second_half, zero_vec);
    
    // 将比较结果合并成一个32位掩码
    let mask1 = _mm_movemask_epi8(cmp1) as u32;
    let mask2 = _mm_movemask_epi8(cmp2) as u32;
    let mask = (mask2 << 16) | mask1;

    // `!mask` 会找到第一个非零字节的位置
    let first_nonzero_byte_idx = (!mask).trailing_zeros();
    if first_nonzero_byte_idx >= 32 {
        256 // 所有字节都为零
    } else {
        first_nonzero_byte_idx * 8 + hash[first_nonzero_byte_idx as usize].leading_zeros()
    }
}

/// AVX-512 (BW/VL) 优化版本，用于计算前导零。
/// 这是目前x86_64平台上最高效的实现。
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512bw,avx512vl")]
unsafe fn count_leading_zeros_avx512(hash: &[u8; 32]) -> u32 {
    // 使用 _mm256_loadu_si256 一次性加载整个32字节哈希到 ymm 寄存器。
    let data_vec = _mm256_loadu_si256(hash.as_ptr() as *const __m256i);
    let zero_vec = _mm256_setzero_si256();

    // _mm256_cmpeq_epi8_mask 直接比较32个字节，并返回一个 u32 掩码。
    // 如果一个字节为0，则对应位为1，否则为0。
    let mask = _mm256_cmpeq_epi8_mask(data_vec, zero_vec);

    // `!mask` 将掩码反转，第一个非零字节对应的位现在是0，其他是1。
    // `_tzcnt_u32` (trailing_zeros) 会找到第一个0的位置，即第一个非零字节的索引。
    // 这个指令来自 BMI1，比迭代查找快得多。
    let first_nonzero_byte_idx = _tzcnt_u32(!mask);

    // 如果所有字节都为零 (idx >= 32)，则返回256。否则计算总的前导零位数。
    first_nonzero_byte_idx * 8 + hash.get(first_nonzero_byte_idx as usize).map_or(0, |&b| b.leading_zeros())
}

/// 超高性能挑战前缀 - 专为高难度优化
#[repr(align(64))]
struct HighDifficultyPrefix {
    data: [u8; MAX_CHALLENGE_LEN + 32],
    challenge_len: usize,
    _padding: [u8; CACHE_LINE_SIZE],
}

impl HighDifficultyPrefix {
    fn new(challenge: &str) -> Self {
        let mut data = [0u8; MAX_CHALLENGE_LEN + 32];
        let challenge_bytes = challenge.as_bytes();
        let challenge_len = challenge_bytes.len();
        data[..challenge_len].copy_from_slice(challenge_bytes);
        
        Self {
            data,
            challenge_len,
            _padding: [0u8; CACHE_LINE_SIZE],
        }
    }
    
    /// 超高效批量消息创建 - 针对高难度优化
    #[inline(always)]
    fn create_message_mega_batch(&mut self, start_nonce: u64, batch_size: usize, 
                                messages: &mut [[u8; MAX_CHALLENGE_LEN + 32]], 
                                message_lengths: &mut [usize]) {
        // 使用SIMD友好的批处理方式
        for i in 0..batch_size {
            let nonce = start_nonce + i as u64;
            let mut buffer = itoa::Buffer::new();
            let nonce_str = buffer.format(nonce);
            let nonce_bytes = nonce_str.as_bytes();
            let nonce_len = nonce_bytes.len();
            
            let message_len = self.challenge_len + nonce_len;
            
            // 优化的内存拷贝
            messages[i][..self.challenge_len].copy_from_slice(&self.data[..self.challenge_len]);
            messages[i][self.challenge_len..message_len].copy_from_slice(nonce_bytes);
            message_lengths[i] = message_len;
            
            // 清零剩余部分确保一致性
            messages[i][message_len..].fill(0);
        }
    }
}

/// 高难度专用SHA256处理器 - 智能早退
struct HighDifficultySha256Processor {
    hashers: Vec<(Sha256, Sha256)>,
}

impl HighDifficultySha256Processor {
    fn new(batch_size: usize) -> Self {
        let mut hashers = Vec::with_capacity(batch_size);
        for _ in 0..batch_size {
            hashers.push((Sha256::new(), Sha256::new()));
        }
        
        Self { hashers }
    }
    
    /// 高难度批量处理 - 带早退优化
    #[inline(always)]
    fn batch_process_high_difficulty(&mut self, 
                                   messages: &[[u8; MAX_CHALLENGE_LEN + 32]], 
                                   lengths: &[usize], 
                                   results: &mut [[u8; 32]],
                                   start_nonce: u64,
                                   threshold: u32) -> Option<PowResult> {
        
        let batch_size = messages.len();
        let early_exit = get_global_stats().early_exit_enabled.load(Ordering::Acquire);
        
        for i in 0..batch_size {
            let (hasher1, hasher2) = &mut self.hashers[i];
            
            // 第一轮SHA256
            hasher1.reset();
            hasher1.update(&messages[i][..lengths[i]]);
            let hash1 = hasher1.finalize_reset();
            
            // 高难度模式：在第一轮后快速检查
            if early_exit && threshold >= 10 {
                let partial_zeros = u32::from_be_bytes([hash1[0], hash1[1], hash1[2], hash1[3]]).leading_zeros();
                if partial_zeros < threshold - 8 {
                    continue; // 第一轮就不符合，跳过第二轮
                }
            }
            
            // 第二轮SHA256
            hasher2.reset();
            hasher2.update(&hash1);
            results[i] = hasher2.finalize_reset().into();
            
            // 立即检查结果
            let leading_zeros = count_leading_zeros_high_diff_simd(&results[i]);
            
            if leading_zeros >= threshold {
                return Some(PowResult {
                    nonce: start_nonce + i as u64,
                    hash_hex: hex::encode(results[i]),
                    leading_zero_bits: leading_zeros,
                });
            }
        }
        
        None
    }
}

/// 终极高难度挖矿函数 - 专攻10+零
fn mine_high_difficulty_ultimate(
    challenge: &str,
    start_nonce: u64,
    total_nonces: u64,
    threshold_bits: u32,
    found_flag: Arc<AtomicU32>, // found_flag is not used in stream mode, but kept for signature consistency
    adaptive_batch: bool,
    chunk_size_arg: usize,
) -> Option<PowResult> {
    
    thread_local! {
        static PREFIX: std::cell::RefCell<HighDifficultyPrefix> = 
            std::cell::RefCell::new(HighDifficultyPrefix::new(""));
        static PROCESSOR: std::cell::RefCell<HighDifficultySha256Processor> = 
            std::cell::RefCell::new(HighDifficultySha256Processor::new(ULTRA_BATCH_SIZE));
        static MESSAGES: std::cell::RefCell<Vec<[u8; MAX_CHALLENGE_LEN + 32]>> = 
            std::cell::RefCell::new(vec![[0u8; MAX_CHALLENGE_LEN + 32]; ULTRA_BATCH_SIZE]);
        static MESSAGE_LENGTHS: std::cell::RefCell<Vec<usize>> = 
            std::cell::RefCell::new(vec![0usize; ULTRA_BATCH_SIZE]);
        static RESULTS: std::cell::RefCell<Vec<[u8; 32]>> = 
            std::cell::RefCell::new(vec![[0u8; 32]; ULTRA_BATCH_SIZE]);
    }
    
    let is_high_difficulty = threshold_bits >= 10;
    
    // 动态批处理大小
    let mut chunk_size = if adaptive_batch && chunk_size_arg == 65536 {
        get_global_stats().calculate_adaptive_batch_size()
    } else {
        chunk_size_arg
    };
    // 确保内部块大小不超过线程本地缓冲区的容量
    chunk_size = chunk_size.min(ULTRA_BATCH_SIZE).min(total_nonces as usize);
    
    if chunk_size == 0 { return None; }
    
    (0..total_nonces as usize)
        .into_par_iter()
        .chunks(chunk_size)
        .find_map_any(|chunk_indices| {
            let chunk_start_nonce = start_nonce + chunk_indices[0] as u64;
            let actual_batch_size = chunk_indices.len();
            
            PREFIX.with(|p| {
                let mut prefix = p.borrow_mut();
                if prefix.challenge_len == 0 {
                    *prefix = HighDifficultyPrefix::new(challenge);
                }

                PROCESSOR.with(|proc| {
                    MESSAGES.with(|msgs| {
                        MESSAGE_LENGTHS.with(|lens| {
                            RESULTS.with(|res| {
                                let mut processor = proc.borrow_mut();
                                let mut messages = msgs.borrow_mut();
                                let mut message_lengths = lens.borrow_mut();
                                let mut results = res.borrow_mut();

                                // 创建批量消息
                                prefix.create_message_mega_batch(
                                    chunk_start_nonce, 
                                    actual_batch_size, 
                                    &mut messages[..actual_batch_size], 
                                    &mut message_lengths[..actual_batch_size]
                                );

                                // 高难度优化处理
                                let result = processor.batch_process_high_difficulty(
                                    &messages[..actual_batch_size],
                                    &message_lengths[..actual_batch_size],
                                    &mut results[..actual_batch_size],
                                    chunk_start_nonce,
                                    threshold_bits
                                );

                                // 更新统计
                                get_global_stats().add_hashes(actual_batch_size as u64, is_high_difficulty);

                                // 检查是否找到结果
                                if let Some(ref found_result) = result {
                                    found_flag.store(found_result.leading_zero_bits, Ordering::Release);
                                    get_global_stats().update_best(found_result.leading_zero_bits);
                                }

                                result
                            })
                        })
                    })
                })
            })
        })
}

/// 高难度流模式 - 智能难度攀升
fn mine_high_difficulty_stream(
    challenge: &str,
    start_nonce: u64,
    total_nonces: u64,
    baseline_bits: u32,
    adaptive_batch: bool,
    chunk_size_arg: usize,
) -> Option<PowResult> {
    
    thread_local! {
        static PREFIX: std::cell::RefCell<HighDifficultyPrefix> = 
            std::cell::RefCell::new(HighDifficultyPrefix::new(""));
        static PROCESSOR: std::cell::RefCell<HighDifficultySha256Processor> = 
            std::cell::RefCell::new(HighDifficultySha256Processor::new(ULTRA_BATCH_SIZE));
        static MESSAGES: std::cell::RefCell<Vec<[u8; MAX_CHALLENGE_LEN + 32]>> = 
            std::cell::RefCell::new(vec![[0u8; MAX_CHALLENGE_LEN + 32]; ULTRA_BATCH_SIZE]);
        static MESSAGE_LENGTHS: std::cell::RefCell<Vec<usize>> = 
            std::cell::RefCell::new(vec![0usize; ULTRA_BATCH_SIZE]);
        static RESULTS: std::cell::RefCell<Vec<[u8; 32]>> = 
            std::cell::RefCell::new(vec![[0u8; 32]; ULTRA_BATCH_SIZE]);
    }

    let current_best_bits = Arc::new(AtomicU32::new(baseline_bits));
    let is_high_difficulty = baseline_bits >= 10;
    
    let mut chunk_size = if adaptive_batch && chunk_size_arg == 65536 { // Only use adaptive if chunk_size is default
        get_global_stats().calculate_adaptive_batch_size()
    } else {
        chunk_size_arg
    };
    // 确保内部块大小不超过线程本地缓冲区的容量
    chunk_size = chunk_size.min(ULTRA_BATCH_SIZE).min(total_nonces as usize);
    
    (0..total_nonces as usize)
        .into_par_iter()
        .chunks(chunk_size)
        .filter_map(|chunk_indices| {
            let chunk_start_nonce = start_nonce + chunk_indices[0] as u64;
            let actual_batch_size = chunk_indices.len();
            
            PREFIX.with(|p| {
                let mut prefix = p.borrow_mut();
                if prefix.challenge_len == 0 {
                    *prefix = HighDifficultyPrefix::new(challenge);
                }

                PROCESSOR.with(|proc| {
                    MESSAGES.with(|msgs| {
                        MESSAGE_LENGTHS.with(|lens| {
                            RESULTS.with(|res| {
                                let mut processor = proc.borrow_mut();
                                let mut messages = msgs.borrow_mut();
                                let mut message_lengths = lens.borrow_mut();
                                let mut results = res.borrow_mut();

                                prefix.create_message_mega_batch(
                                    chunk_start_nonce, 
                                    actual_batch_size, 
                                    &mut messages[..actual_batch_size], 
                                    &mut message_lengths[..actual_batch_size]
                                );

                                // 批量计算SHA256
                                for i in 0..actual_batch_size {
                                    let (hasher1, hasher2) = &mut processor.hashers[i];
                                    
                                    hasher1.reset();
                                    hasher1.update(&messages[i][..message_lengths[i]]);
                                    let hash1 = hasher1.finalize_reset();
                                    
                                    hasher2.reset();
                                    hasher2.update(&hash1);
                                    results[i] = hasher2.finalize_reset().into();
                                }

                                get_global_stats().add_hashes(actual_batch_size as u64, is_high_difficulty);

                                // 寻找最佳结果
                                let mut local_best: Option<PowResult> = None;
                                let current_best = current_best_bits.load(Ordering::Acquire);

                                for i in 0..actual_batch_size {
                                    let leading_zeros = count_leading_zeros_high_diff_simd(&results[i]);
                                    
                                    if leading_zeros > current_best && 
                                       (local_best.is_none() || leading_zeros > local_best.as_ref().unwrap().leading_zero_bits) {
                                        current_best_bits.fetch_max(leading_zeros, Ordering::Relaxed);
                                        get_global_stats().update_best(leading_zeros);
                                        
                                        local_best = Some(PowResult {
                                            nonce: chunk_start_nonce + i as u64,
                                            hash_hex: hex::encode(results[i]),
                                            leading_zero_bits: leading_zeros,
                                        });
                                    }
                                }
                                
                                local_best
                            })
                        })
                    })
                })
            })
        })
        .reduce_with(|a, b| if a.leading_zero_bits >= b.leading_zero_bits { a } else { b })
}

fn setup_high_difficulty_environment(args: &Args) {
    let thread_count = if args.threads > 0 {
        args.threads
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(96)
            .min(128)
    };
    
    rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .thread_name(|i| format!("high-diff-{}", i))
        .build_global()
        .expect("Failed to build high difficulty thread pool");
    
    eprintln!("🚀 高难度优化配置: {} 线程, 超级模式: {}, 自适应批处理: {}", 
        thread_count, args.ultra_mode, args.adaptive_batch);
}

fn write_output(output_json: &serde_json::Value, output_path: &Option<String>, append: bool) {
    let output_string = serde_json::to_string_pretty(output_json).unwrap();

    if let Some(path) = output_path {
        use std::fs::OpenOptions;
        use std::io::Write;

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(append)
            .open(path)
            .unwrap_or_else(|e| panic!("无法打开输出文件 '{}': {}", path, e));
        
        writeln!(file, "{}", output_string).unwrap_or_else(|e| panic!("无法写入文件 '{}': {}", path, e));
    } else {
        println!("{}", output_string);
    }
}

fn run(args: Args) -> Result<(), String> {
    setup_high_difficulty_environment(&args);

    if args.threshold.is_some() && args.stream {
        return Err("错误: --threshold 和 --stream 参数是互斥的。".to_string());
    }

    let challenge = format!("{}:{}", args.txid, args.vout);
    if challenge.len() > MAX_CHALLENGE_LEN {
        return Err(format!("错误: challenge 长度超过 {} 字节。", MAX_CHALLENGE_LEN));
    }

    if args.stream {
        run_stream_mode_high_difficulty(args, &challenge)?;
    } else {
        run_threshold_mode_high_difficulty(args, &challenge)?;
    }
    Ok(())
}

fn run_stream_mode_high_difficulty(args: Args, challenge: &str) -> Result<(), String> {
    let mut baseline = args.baseline;
    let mut current_nonce = args.start;
    let batch_size = args.batch;

    if batch_size == 0 {
        return Err("错误: --batch 大小不能为0。".to_string());
    }
    
    eprintln!("🚀 高难度流模式启动...");
    println!("进入高难度持续模式... Challenge: '{}', 初始基线: {}", challenge, baseline);

    loop {
        let start_time = Instant::now();
        if let Some(res) = mine_high_difficulty_stream(
            challenge, 
            current_nonce, 
            batch_size, 
            baseline,
            args.adaptive_batch,
            args.chunk_size,
        ) {
            if res.leading_zero_bits > baseline {
                baseline = res.leading_zero_bits;
                let hashrate = get_global_stats().get_hashrate_mhs();
                let high_diff_ratio = get_global_stats().get_high_difficulty_ratio();
                let adaptive_size = get_global_stats().calculate_adaptive_batch_size();
                
                let output = serde_json::json!({
                    "mode": "high_difficulty_stream",
                    "challenge": challenge,
                    "best": res,
                    "baseline": baseline,
                    "cpu_model": "AMD_EPYC_7K62_HighDiff",
                    "hashrate_mhs": hashrate,
                    "high_difficulty_ratio": high_diff_ratio,
                    "adaptive_batch_size": adaptive_size,
                    "optimizations": {
                        "ultra_mode": args.ultra_mode,
                        "adaptive_batch": args.adaptive_batch,
                        "early_exit": baseline >= 10
                    }
                });
                write_output(&output, &args.output, true);
            }
        }
        
        let duration = start_time.elapsed();
        let current_hashrate = (batch_size as f64 / duration.as_secs_f64()) / 1_000_000.0;
        let global_hashrate = get_global_stats().get_hashrate_mhs();
        let adaptive_size = get_global_stats().calculate_adaptive_batch_size();
        
        let next_nonce = current_nonce + batch_size;
        eprintln!(
            "[高难度] 批次 [{}..{}] 完成. 耗时: {:.2?}, 当前: {:.1} MH/s, 全局: {:.1} MH/s, 基线: {}, 批处理: {}",
            current_nonce,
            next_nonce - 1,
            duration,
            current_hashrate,
            global_hashrate,
            baseline,
            adaptive_size
        );
        current_nonce = next_nonce;
    }
}

fn run_threshold_mode_high_difficulty(args: Args, challenge: &str) -> Result<(), String> {
    let threshold = args.threshold.ok_or("错误: 阈值模式下必须提供 --threshold 参数。")?;

    eprintln!("🚀 高难度阈值模式启动...");
    println!(
        "进入高难度阈值模式... Challenge: '{}', 阈值: {}, 搜索范围: [{}..{}]",
        challenge,
        threshold,
        args.start,
        args.start + args.count - 1
    );

    let found_flag = Arc::new(AtomicU32::new(0));
    let start_time = Instant::now();
    
    let result = mine_high_difficulty_ultimate(
        challenge, 
        args.start, 
        args.count, 
        threshold, 
        found_flag,
        args.adaptive_batch,
        args.chunk_size,
    );
    
    let duration = start_time.elapsed();
    let global_hashrate = get_global_stats().get_hashrate_mhs();
    let high_diff_ratio = get_global_stats().get_high_difficulty_ratio();

    eprintln!(
        "[高难度] 搜索完成. 耗时: {:.2?}, 平均算力: {:.1} MH/s, 高难度占比: {:.1}%",
        duration, global_hashrate, high_diff_ratio * 100.0
    );

    let output = serde_json::json!({
        "mode": "high_difficulty_threshold",
        "challenge": challenge,
        "threshold": threshold,
        "result": result,
        "cpu_model": "AMD_EPYC_7K62_HighDiff",
        "hashrate_mhs": global_hashrate,
        "duration_secs": duration.as_secs_f64(),
        "total_hashes": get_global_stats().total_hashes.load(Ordering::Relaxed),
        "high_difficulty_hashes": get_global_stats().high_difficulty_hashes.load(Ordering::Relaxed),
        "high_difficulty_ratio": high_diff_ratio,
        "optimizations": {
            "ultra_mode": args.ultra_mode,
            "adaptive_batch": args.adaptive_batch,
            "early_exit_enabled": threshold >= 10,
            "batch_size": get_global_stats().calculate_adaptive_batch_size()
        }
    });
    write_output(&output, &args.output, false);
    Ok(())
}

fn main() {
    let args = Args::parse();
    if let Err(e) = run(args) {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_high_difficulty_leading_zeros() {
        // 测试不同难度的前导零计算
        let mut hash_easy = [0u8; 32];
        hash_easy[0] = 0x0f;
        assert_eq!(count_leading_zeros_high_difficulty_optimized(&hash_easy), 4);

        // 测试10个零的情况 (前5个字节为0, 第6个字节为0x0f)
        let mut hash_10_zeros = [0u8; 32];
        hash_10_zeros[0] = 0x00;
        hash_10_zeros[1] = 0x03; // 6位前导零，总共8+6=14位
        assert_eq!(count_leading_zeros_high_difficulty_optimized(&hash_10_zeros), 14);

        // 测试全零
        let hash_all_zeros = [0u8; 32];
        assert_eq!(count_leading_zeros_high_difficulty_optimized(&hash_all_zeros), 256);
    }

    #[test]
    fn test_adaptive_batch_sizing() {
        let stats = HighDifficultyStats::new();
        
        // 测试不同难度下的批处理大小
        assert_eq!(stats.calculate_adaptive_batch_size(), ULTRA_BATCH_SIZE); // 初始状态
        
        stats.update_best(8);
        assert_eq!(stats.calculate_adaptive_batch_size(), ULTRA_BATCH_SIZE * 2); // 8个零：2倍大小
        
        stats.update_best(12);
        assert_eq!(stats.calculate_adaptive_batch_size(), ULTRA_BATCH_SIZE * 4); // 12个零：4倍大小
        
        stats.update_best(18);
        assert_eq!(stats.calculate_adaptive_batch_size(), ULTRA_BATCH_SIZE * 8); // 18个零：8倍大小
    }

    #[test]
    fn test_high_difficulty_prefix() {
        let mut prefix = HighDifficultyPrefix::new("test:1");
        let start_nonce = 100000u64;
        let batch_size = 3;
        let mut messages = vec![[0u8; MAX_CHALLENGE_LEN + 32]; batch_size];
        let mut message_lengths = vec![0usize; batch_size];
        
        prefix.create_message_mega_batch(start_nonce, batch_size, &mut messages, &mut message_lengths);
        
        // 验证第一个消息
        let msg1_str = std::str::from_utf8(&messages[0][..message_lengths[0]]).unwrap();
        assert_eq!(msg1_str, "test:1100000");
        
        // 验证第二个消息
        let msg2_str = std::str::from_utf8(&messages[1][..message_lengths[1]]).unwrap();
        assert_eq!(msg2_str, "test:1100001");
    }

    #[test]
    fn test_high_difficulty_processor() {
        let mut processor = HighDifficultySha256Processor::new(2);
        let messages = [
            {
                let mut msg = [0u8; MAX_CHALLENGE_LEN + 32];
                msg[..5].copy_from_slice(b"hello");
                msg
            },
            {
                let mut msg = [0u8; MAX_CHALLENGE_LEN + 32];
                msg[..5].copy_from_slice(b"world");
                msg
            }
        ];
        let lengths = [5, 5];
        let mut results = [[0u8; 32]; 2];
        
        // 测试批量处理（使用低阈值确保不会早退）
        let result = processor.batch_process_high_difficulty(&messages, &lengths, &mut results, 0, 1);
        
        // 验证结果不为零（实际哈希值）
        assert_ne!(results[0], [0u8; 32]);
        assert_ne!(results[1], [0u8; 32]);
        // 验证不同输入产生不同哈希
        assert_ne!(results[0], results[1]);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_simd_high_difficulty() {
        let test_hashes = [
            [0u8; 32], // 全零
            {
                let mut h = [0u8; 32];
                h[0] = 0x0f;
                h
            }, // 4个前导零
            {
                let mut h = [0u8; 32];
                h[1] = 0x03; // 第一字节为0，第二字节的前6位为0，总共14位
                h
            }
        ];

        for hash in &test_hashes {
            let scalar_result = count_leading_zeros_high_difficulty_optimized(hash);
            let simd_result = count_leading_zeros_high_diff_simd(hash);
            assert_eq!(scalar_result, simd_result, 
                "SIMD和标量结果不匹配，hash: {:?}, scalar: {}, simd: {}", 
                hash, scalar_result, simd_result);
        }
    }

    #[test]
    fn test_early_exit_mechanism() {
        let stats = HighDifficultyStats::new();
        
        // 初始状态：早退未启用
        assert!(!stats.early_exit_enabled.load(Ordering::Acquire));
        
        // 低难度：早退仍未启用
        stats.update_best(8);
        assert!(!stats.early_exit_enabled.load(Ordering::Acquire));
        
        // 高难度：启用早退
        stats.update_best(12);
        assert!(stats.early_exit_enabled.load(Ordering::Acquire));
    }

    #[test]
    fn test_statistics_tracking() {
        let stats = HighDifficultyStats::new();
        
        // 添加一些哈希计算
        stats.add_hashes(1000, false); // 普通难度
        stats.add_hashes(500, true);   // 高难度
        
        assert_eq!(stats.total_hashes.load(Ordering::Relaxed), 1500);
        assert_eq!(stats.high_difficulty_hashes.load(Ordering::Relaxed), 500);
        
        let ratio = stats.get_high_difficulty_ratio();
        assert!((ratio - 1.0/3.0).abs() < 0.001); // 500/1500 ≈ 0.333
    }
}

// 更新的 Cargo.toml 配置 - 专为高难度优化:
/*
[package]
name = "high_difficulty_miner"
version = "2.0.0"
edition = "2021"

[dependencies]
clap = { version = "4.0", features = ["derive"] }
rayon = "1.8"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
sha2 = "0.10"
hex = "0.4"
itoa = "1.0"

[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "abort"
overflow-checks = false

# 专为高难度挖矿优化的编译选项
[target.x86_64-unknown-linux-gnu]
rustflags = [
    "-C", "target-cpu=znver2",
    "-C", "target-feature=+avx2,+bmi1,+bmi2,+fma,+popcnt",
    "-C", "llvm-args=-enable-machine-outliner=never",
    "-C", "llvm-args=-disable-tail-calls=false"
]

# 高性能链接选项
[target.x86_64-unknown-linux-gnu.linker]
rustflags = ["-C", "link-arg=-Wl,--as-needed"]
*/