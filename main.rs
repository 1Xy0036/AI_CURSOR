use clap::Parser;
use crossbeam_channel::Receiver;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Instant;

const MAX_CHALLENGE_LEN: usize = 96;
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
    #[arg(long, default_value_t = 1_000_000)]
    count: u64,

    /// 每轮批大小 (持续模式)
    #[arg(long, default_value_t = 1_000_000)]
    batch: u64,

    /// 持续模式初始基线 (前导零位)
    #[arg(long, default_value_t = 0)]
    baseline: u32,
}

/// 用于存储计算结果的结构体
#[derive(Debug, Serialize, Deserialize, Clone)]
struct PowResult {
    nonce: u64,
    hash_hex: String,
    leading_zero_bits: u32,
}

/// 计算给定哈希值的前导零位数
fn count_leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut zero_bits = 0;
    for &byte in hash {
        if byte == 0 {
            zero_bits += 8;
        } else {
            zero_bits += byte.leading_zeros();
            break;
        }
    }
    zero_bits
}

/// 核心的 PoW 计算函数 (阈值模式优化版)
/// 使用 Rayon 的 find_map_any 进行高效并行搜索，找到一个即停止。
fn mine_cpu(
    challenge: &str,
    start_nonce: u64,
    total_nonces: u64,
    threshold_bits: u32,
) -> Option<PowResult> {
    (start_nonce..start_nonce + total_nonces)
        .into_par_iter()
        .find_map_any(|nonce| {
            // 优化点1: 为每个线程创建可复用的缓冲区，避免循环内字符串分配
            let mut buffer = [0u8; MAX_CHALLENGE_LEN + 20]; // 20 for u64 max len
            let challenge_bytes = challenge.as_bytes();
            let chal_len = challenge_bytes.len();
            buffer[..chal_len].copy_from_slice(challenge_bytes);

            // 优化点2: 使用 itoa 将 nonce 直接写入缓冲区，无堆分配
            let mut num_buf = itoa::Buffer::new();
            let nonce_str = num_buf.format(nonce);
            let nonce_len = nonce_str.len();
            buffer[chal_len..chal_len + nonce_len].copy_from_slice(nonce_str.as_bytes());

            let msg_len = chal_len + nonce_len;

            // 2. 计算 double-SHA256
            let hash1 = Sha256::digest(&buffer[..msg_len]);
            let hash2 = Sha256::digest(hash1);

            // 3. 检查难度
            let leading_zeros = count_leading_zero_bits(hash2.as_slice().try_into().unwrap());

            if leading_zeros >= threshold_bits {
                Some(PowResult {
                    nonce,
                    hash_hex: hex::encode(hash2),
                    leading_zero_bits: leading_zeros,
                })
            } else {
                None
            }
        })
}

/// 核心的 PoW 计算函数 (持续模式优化版)
/// 在一个批次内并行搜索，并返回找到的难度最高的结果。
fn mine_cpu_stream(
    challenge: &str,
    start_nonce: u64,
    total_nonces: u64,
    baseline_bits: u32,
) -> Option<PowResult> {
    let results: Receiver<PowResult> = {
        let (sender, receiver) = crossbeam_channel::unbounded();
        (start_nonce..start_nonce + total_nonces)
            .into_par_iter()
            .for_each_with(sender, |s, nonce| {
                let mut buffer = [0u8; MAX_CHALLENGE_LEN + 20];
                let challenge_bytes = challenge.as_bytes();
                let chal_len = challenge_bytes.len();
                buffer[..chal_len].copy_from_slice(challenge_bytes);

                let mut num_buf = itoa::Buffer::new();
                let nonce_str = num_buf.format(nonce);
                let nonce_len = nonce_str.len();
                buffer[chal_len..chal_len + nonce_len].copy_from_slice(nonce_str.as_bytes());

                let msg_len = chal_len + nonce_len;

                let hash1 = Sha256::digest(&buffer[..msg_len]);
                let hash2 = Sha256::digest(hash1);

                let leading_zeros = count_leading_zero_bits(hash2.as_slice().try_into().unwrap());

                if leading_zeros >= baseline_bits {
                    s.send(PowResult { nonce, hash_hex: hex::encode(hash2), leading_zero_bits: leading_zeros }).ok();
                }
            });
        receiver
    };

    results.try_iter().max_by_key(|r| r.leading_zero_bits)
}

fn main() {
    let args = Args::parse();

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
        // --- 持续模式 ---
        let mut baseline = args.baseline;
        let mut current_nonce = args.start;
        let batch_size = args.batch;
        println!("进入持续模式... Challenge: '{}', 初始基线: {}", challenge, baseline);

        loop {
            let start_time = Instant::now();
            if let Some(res) = mine_cpu_stream(&challenge, current_nonce, batch_size, baseline) {
                if res.leading_zero_bits >= baseline {
                    baseline = res.leading_zero_bits;
                    let output = serde_json::json!({
                        "mode": "stream",
                        "challenge": challenge,
                        "best": res,
                        "baseline": baseline
                    });
                    println!("{}", serde_json::to_string(&output).unwrap());
                }
            }
            let duration = start_time.elapsed();
            let hashes_per_sec = (batch_size as f64 / duration.as_secs_f64()) / 1_000_000.0;
            eprintln!(
                "批次 [{}..{}] 处理完毕. 耗时: {:.2?}, 算力: {:.2} MH/s. 当前基线: {}",
                current_nonce,
                current_nonce + batch_size - 1,
                duration,
                hashes_per_sec,
                baseline
            );
            current_nonce += batch_size;
        }
    } else {
        // --- 阈值模式 ---
        let threshold = match args.threshold {
            Some(t) => t,
            None => {
                eprintln!("错误: 阈值模式下必须提供 --threshold 参数，或使用 --stream 模式。");
                return;
            }
        };

        println!(
            "进入阈值模式... Challenge: '{}', 阈值: {}, 搜索范围: [{}..{}]",
            challenge,
            threshold,
            args.start,
            args.start + args.count - 1
        );

        let start_time = Instant::now();
        let result = mine_cpu(&challenge, args.start, args.count, threshold);
        let duration = start_time.elapsed();
        let hashes_per_sec = (args.count as f64 / duration.as_secs_f64()) / 1_000_000.0;

        eprintln!(
            "搜索完成. 耗时: {:.2?}, 平均算力: {:.2} MH/s",
            duration, hashes_per_sec
        );

        let output = serde_json::json!({
            "mode": "threshold",
            "challenge": challenge,
            "threshold": threshold,
            "result": result
        });
        println!("{}", serde_json::to_string(&output).unwrap());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_leading_zeros() {
        let mut hash1 = [0u8; 32];
        assert_eq!(count_leading_zero_bits(&hash1), 256);

        hash1[0] = 0b0000_1111; // 4 leading zeros
        assert_eq!(count_leading_zero_bits(&hash1), 4);

        let mut hash2 = [0u8; 32];
        hash2[0] = 0xff;
        assert_eq!(count_leading_zero_bits(&hash2), 0);

        let mut hash3 = [0u8; 32];
        hash3[0] = 0;
        hash3[1] = 0;
        hash3[2] = 0b0100_0000; // 8 + 8 + 1 = 17 leading zeros
        assert_eq!(count_leading_zero_bits(&hash3), 17);
    }
}