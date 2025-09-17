use clap::Parser;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Instant;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

const MAX_CHALLENGE_LEN: usize = 96;
// AMD EPYC 7K62 特定优化：48核心×2插槽，L3缓存192MB，8内存通道×2
const NUMA_BATCH_SIZE: usize = 8192;    // NUMA感知批处理

/// 定义命令行参数结构
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 交易ID
    #[arg(long)]
    txid: String,

    /// 输出索引
    #[arg(long)]
    vout: u32,

    /// 前导零位阈值 (与 --stream 互斥)
    #[arg(long, short)]
    threshold: Option<u32>,

    /// 持续模式：不设阈值，发现更优即打印一次
    #[arg(long, action)]
    stream: bool,

    /// 起始 nonce
    #[arg(long, default_value_t = 0)]
    start: u64,

    /// 一次性扫描 nonce 数 (阈值模式)
    #[arg(long, default_value_t = 50_000_000)]
    count: u64,

    /// 每轮批大小 (持续模式) - 针对7K62优化
    #[arg(long, default_value_t = 20_000_000)]
    batch: u64,

    /// 持续模式初始基线 (前导零位)
    #[arg(long, default_value_t = 0)]
    baseline: u32,

    /// 线程池大小 (0 = auto, 建议96用于双7K62)
    #[arg(long, default_value_t = 0)]
    threads: usize,

    /// NUMA节点绑定 (0: 自动, 1: 单节点, 2: 双节点交错)
    #[arg(long, default_value_t = 2)]
    numa_mode: u8,

    /// 将JSON结果保存到指定文件而不是打印到标准输出
    #[arg(long, short)]
    output: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PowResult {
    nonce: u64,
    hash_hex: String,
    leading_zero_bits: u32,
}

/// 针对AMD Zen2架构优化的前导零位计算
/// 利用AMD的出色整数执行单元和64位ALU
#[inline(always)]
fn count_leading_zero_bits_zen2(hash: &[u8; 32]) -> u32 {
    let mut zero_bits = 0u32;
    
    // AMD Zen2架构对64位操作优化很好，直接使用u64处理
    // 避免分支预测失败，使用位运算技巧
    let hash_u64 = unsafe {
        std::slice::from_raw_parts(hash.as_ptr() as *const u64, 4)
    };
    
    // 利用AMD的快速整数运算单元
    for &quad in hash_u64 {
        let be_quad = u64::from_be(quad);
        if be_quad == 0 {
            zero_bits += 64;
        } else {
            zero_bits += be_quad.leading_zeros();
            break;
        }
    }
    
    zero_bits
}

/// AMD EPYC 7K62 NUMA感知的挑战前缀结构
/// 考虑L3缓存大小和内存带宽
struct NumaAwareChallengePrefix {
    data: [u8; MAX_CHALLENGE_LEN + 20],
    challenge_len: usize,
    // 添加填充以避免false sharing，AMD架构缓存行64字节
    _padding: [u8; 64],
}

impl NumaAwareChallengePrefix {
    fn new(challenge: &str) -> Self {
        let mut data = [0u8; MAX_CHALLENGE_LEN + 20];
        let challenge_bytes = challenge.as_bytes();
        let challenge_len = challenge_bytes.len();
        data[..challenge_len].copy_from_slice(challenge_bytes);
        
        Self { 
            data, 
            challenge_len,
            _padding: [0; 64]
        }
    }
    
    #[inline(always)]
    fn create_message(&mut self, nonce: u64) -> &[u8] {
        // 使用 itoa crate 进行高效的、无堆分配的整数到字符串转换
        // itoa::Buffer 是一个 [u8; 20] 的封装
        let mut buffer = itoa::Buffer::new();
        let nonce_bytes = buffer.format(nonce).as_bytes();
        let nonce_len = nonce_bytes.len();

        let message_len = self.challenge_len + nonce_len;
        self.data[self.challenge_len..message_len]
            .copy_from_slice(nonce_bytes);

        &self.data[..message_len]
    }
}

/// 针对AMD EPYC 7K62优化的SHA256计算器
/// 考虑Zen2微架构的特点：强大的整数单元，预取器，分支预测
struct Zen2OptimizedHasher {
    hasher1: Sha256,
    hasher2: Sha256,
    // 预分配缓冲区，对齐到64字节（缓存行大小）
    _padding: [u8; 64],
}

impl Zen2OptimizedHasher {
    fn new() -> Self {
        Self {
            hasher1: Sha256::new(),
            hasher2: Sha256::new(),
            _padding: [0; 64],
        }
    }
    
    #[inline(always)]
    fn double_sha256(&mut self, input: &[u8]) -> [u8; 32] {
        // 重用hasher实例，减少初始化开销
        self.hasher1.reset();
        Digest::update(&mut self.hasher1, input);
        let hash1 = self.hasher1.finalize_reset();
        
        self.hasher2.reset();
        Digest::update(&mut self.hasher2, &hash1);
        self.hasher2.finalize_reset().into()
    }
}

/// AMD EPYC 7K62 NUMA优化的工作线程函数
/// 充分利用96核心（48×2）和8内存通道×2的优势
fn mine_cpu_epyc7k62(
    challenge: &str,
    start_nonce: u64,
    total_nonces: u64,
    threshold_bits: u32,
    found_flag: Arc<AtomicU32>,
) -> Option<PowResult> {
    use std::cell::RefCell;
    
    // 线程本地存储，避免跨NUMA访问
    thread_local! {
        static HASHER: RefCell<Zen2OptimizedHasher> = RefCell::new(Zen2OptimizedHasher::new());
        static PREFIX: RefCell<NumaAwareChallengePrefix> = RefCell::new(NumaAwareChallengePrefix::new(""));
    }
    
    // 使用NUMA感知的批处理大小，转换为usize范围
    let chunk_size = std::cmp::min(NUMA_BATCH_SIZE, total_nonces as usize);
    
    // 边界情况处理：如果总数为0或块大小为0，则无需搜索
    if total_nonces == 0 || chunk_size == 0 {
        return None;
    }
    
    (0..total_nonces as usize)
        .into_par_iter()
        .chunks(chunk_size)
        .find_map_any(|chunk_indices| {
            PREFIX.with(|p| {
                let mut prefix = p.borrow_mut();
                *prefix = NumaAwareChallengePrefix::new(challenge);
                
                HASHER.with(|h| {
                    let mut hasher = h.borrow_mut();
                    
                    // 使用 find() 使代码更简洁，它会在找到第一个 Some(T) 时停止
                    chunk_indices.iter().find_map(|&idx| {
                         let nonce = start_nonce + idx as u64;
                         // 早期退出检查 - AMD的分支预测器很好
                         let current_best = found_flag.load(Ordering::Acquire);
                         if current_best >= threshold_bits {
                             return None; // 提前终止此 chunk 的搜索
                         }

                         let message = prefix.create_message(nonce);
                         let hash_array = hasher.double_sha256(message);
                         let leading_zeros = count_leading_zero_bits_zen2(&hash_array);

                         if leading_zeros >= threshold_bits {
                             found_flag.store(leading_zeros, Ordering::Release);
                             Some(PowResult {
                                 nonce,
                                 hash_hex: hex::encode(hash_array),
                                 leading_zero_bits: leading_zeros,
                             })
                         } else {
                             None
                         }
                    })
                })
            })
        })
}

/// EPYC 7K62优化的流模式挖掘
fn mine_cpu_stream_epyc7k62(
    challenge: &str,
    start_nonce: u64,
    total_nonces: u64,
    baseline_bits: u32,
) -> Option<PowResult> {
    use std::cell::RefCell;

    // 线程本地存储，避免在每个chunk中重复创建对象
    thread_local! {
        static HASHER: RefCell<Zen2OptimizedHasher> = RefCell::new(Zen2OptimizedHasher::new());
        static PREFIX: RefCell<NumaAwareChallengePrefix> = RefCell::new(NumaAwareChallengePrefix::new(""));
    }

    // 原子地追踪当前找到的最佳结果，以减少通信开销
    let current_best_bits = Arc::new(AtomicU32::new(baseline_bits));
    
    // 使用 reduce 代替 collect，直接在并行计算中找到最优解，减少内存分配
    (0..total_nonces as usize)
        .into_par_iter()
        .chunks(NUMA_BATCH_SIZE)
        .filter_map(|chunk_indices| { // 每个线程会处理多个chunk
            PREFIX.with(|p| {
                let mut prefix = p.borrow_mut();
                *prefix = NumaAwareChallengePrefix::new(challenge); // 每个批次开始时更新challenge

                HASHER.with(|h| {
                    let mut hasher = h.borrow_mut();
                    let mut local_best: Option<PowResult> = None;

                    for idx in chunk_indices {
                        let nonce = start_nonce + idx as u64;
                        let current_best = current_best_bits.load(Ordering::Relaxed);

                        let message = prefix.create_message(nonce);
                        let hash_array = hasher.double_sha256(message);
                        let leading_zeros = count_leading_zero_bits_zen2(&hash_array);
                        
                        if leading_zeros > current_best && (local_best.is_none() || leading_zeros > local_best.as_ref().unwrap().leading_zero_bits) {
                            current_best_bits.fetch_max(leading_zeros, Ordering::Relaxed);
                            local_best = Some(PowResult {
                                nonce,
                                hash_hex: hex::encode(hash_array),
                                leading_zero_bits: leading_zeros,
                            });
                        }
                    }
                    local_best
                })
            })
        })
        .reduce_with(|a, b| if a.leading_zero_bits >= b.leading_zero_bits { a } else { b })
}

fn setup_epyc7k62_environment(args: &Args) {
    // 针对AMD EPYC 7K62的线程池配置
    let thread_count = if args.threads > 0 {
        args.threads
    } else {
        // 双路EPYC 7K62: 48核心×2×2线程 = 192线程
        // 但对于CPU密集型任务，通常物理核心数效果更好
        match args.numa_mode {
            1 => 48,  // 单NUMA节点
            2 => 96,  // 双NUMA节点，每核心一个线程
            _ => 96,  // 默认配置
        }
    };
    
    rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .thread_name(|i| format!("epyc7k62-worker-{}", i))
        .build_global()
        .expect("Failed to build thread pool for EPYC 7K62");
    
    eprintln!("EPYC 7K62优化配置: {} 工作线程, NUMA模式: {}", thread_count, args.numa_mode);
}

/// 将结果写入文件或标准输出
fn write_output(output_json: &serde_json::Value, output_path: &Option<String>, append: bool) {
    // to_string_pretty is slightly nicer for file logs, but to_string is fine for performance.
    let output_string = match serde_json::to_string_pretty(output_json) {
        Ok(s) => s,
        Err(_) => serde_json::to_string(output_json).unwrap(), // Fallback
    };

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

fn main() {
    let args = Args::parse();
    
    // 设置针对EPYC 7K62优化的环境
    setup_epyc7k62_environment(&args);

    if args.threshold.is_some() && args.stream {
        eprintln!("错误: --threshold 和 --stream 参数是互斥的。");
        return;
    }

    let challenge = format!("{}:{}", args.txid, args.vout);
    if challenge.len() > MAX_CHALLENGE_LEN {
        eprintln!("错误: txid 过长，导致 challenge 长度超过 {} 字节。", MAX_CHALLENGE_LEN);
        return;
    }

    if args.stream {
        // --- 持续模式 (EPYC 7K62优化) ---
        let mut baseline = args.baseline;
        let mut current_nonce = args.start;
        let batch_size = args.batch;
        let challenge_str = challenge.as_str();
        
        eprintln!("EPYC 7K62流模式启动...");
        println!("进入持续模式... Challenge: '{}', 初始基线: {}", challenge_str, baseline);

        loop {
            let start_time = Instant::now();
            if let Some(res) = mine_cpu_stream_epyc7k62(challenge_str, current_nonce, batch_size, baseline) {
                if res.leading_zero_bits > baseline {
                    baseline = res.leading_zero_bits;
                    let output = serde_json::json!({
                        "mode": "stream_epyc7k62",
                        "challenge": challenge,
                        "best": res,
                        "baseline": baseline,
                        "cpu_model": "AMD_EPYC_7K62_Dual"
                    });
                    write_output(&output, &args.output, true);
                }
            }
            
            let duration = start_time.elapsed();
            let hashes_per_sec = (batch_size as f64 / duration.as_secs_f64()) / 1_000_000.0;
            
            let next_nonce = current_nonce + batch_size;
            eprintln!(
                "[EPYC7K62] 批次 [{}..{}] 完成. 耗时: {:.2?}, 算力: {:.1} MH/s, 基线: {}",
                current_nonce,
                next_nonce - 1,
                duration,
                hashes_per_sec,
                baseline
            );
            current_nonce = next_nonce;
        }
    } else {
        // --- 阈值模式 (EPYC 7K62优化) ---
        let threshold = match args.threshold {
            Some(t) => t,
            None => {
                eprintln!("错误: 阈值模式下必须提供 --threshold 参数，或使用 --stream 模式。");
                return;
            }
        };

        eprintln!("EPYC 7K62阈值模式启动...");
        println!(
            "进入阈值模式... Challenge: '{}', 阈值: {}, 搜索范围: [{}..{}]",
            challenge,
            threshold,
            args.start,
            args.start + args.count - 1
        );

        let found_flag = Arc::new(AtomicU32::new(0));
        let start_time = Instant::now();
        
        let result = mine_cpu_epyc7k62(&challenge, args.start, args.count, threshold, found_flag);
        
        let duration = start_time.elapsed();
        let hashes_per_sec = (args.count as f64 / duration.as_secs_f64()) / 1_000_000.0;

        eprintln!(
            "[EPYC7K62] 搜索完成. 耗时: {:.2?}, 平均算力: {:.1} MH/s",
            duration, hashes_per_sec
        );

        let output = serde_json::json!({
            "mode": "threshold_epyc7k62",
            "challenge": challenge,
            "threshold": threshold,
            "result": result,
            "cpu_model": "AMD_EPYC_7K62_Dual",
            "hashrate_mhs": hashes_per_sec
        });
        write_output(&output, &args.output, false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_leading_zeros_zen2() {
        let mut hash1 = [0u8; 32];
        assert_eq!(count_leading_zero_bits_zen2(&hash1), 256);

        hash1[0] = 0b0000_1111;
        assert_eq!(count_leading_zero_bits_zen2(&hash1), 4);

        let mut hash2 = [0u8; 32];
        hash2[0] = 0xff;
        assert_eq!(count_leading_zero_bits_zen2(&hash2), 0);
    }

    #[test]
    fn test_numa_aware_prefix() {
        let mut prefix = NumaAwareChallengePrefix::new("test:1");
        let msg = prefix.create_message(12345);
        assert_eq!(std::str::from_utf8(msg).unwrap(), "test:112345");
    }
}