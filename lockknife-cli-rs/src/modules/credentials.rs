use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use rayon::prelude::*;
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

use crate::app::{LockKnifeError, Result};

#[derive(Debug, Clone, Serialize)]
pub struct CrackMetadata {
    pub matched: bool,
    pub recovered_secret: Option<String>,
    pub candidate_space: u64,
    pub input_size: u64,
    pub strategy: String,
}

pub fn crack_pin_hash(target_hash_hex: &str, algo: &str, length: u32) -> Result<CrackMetadata> {
    if !(1..=12).contains(&length) {
        return Err(LockKnifeError::message("length must be between 1 and 12"));
    }
    let target = hex::decode(target_hash_hex)
        .map_err(|err| LockKnifeError::message(format!("invalid target hash: {err}")))?;
    let width = length as usize;
    let max = 10_u64
        .checked_pow(length)
        .ok_or_else(|| LockKnifeError::message("length too large"))?;

    let recovered_secret = (0..max).into_par_iter().find_map_any(|candidate| {
        let pin = format!("{candidate:0width$}");
        let digest = digest_for_algo(algo, pin.as_bytes()).ok()?;
        (digest == target).then_some(pin)
    });

    Ok(CrackMetadata {
        matched: recovered_secret.is_some(),
        recovered_secret,
        candidate_space: max,
        input_size: max,
        strategy: format!("offline-bruteforce-pin-{algo}"),
    })
}

pub fn dictionary_attack(target_hash_hex: &str, algo: &str, wordlist: &Path) -> Result<CrackMetadata> {
    let target = hex::decode(target_hash_hex)
        .map_err(|err| LockKnifeError::message(format!("invalid target hash: {err}")))?;
    let words = read_wordlist(wordlist)?;
    let input_size = words.len() as u64;

    let recovered_secret = words.into_par_iter().find_map_any(|word| {
        let digest = digest_for_algo(algo, word.as_bytes()).ok()?;
        (digest == target).then_some(word)
    });

    Ok(CrackMetadata {
        matched: recovered_secret.is_some(),
        recovered_secret,
        candidate_space: input_size,
        input_size,
        strategy: format!("offline-dictionary-{algo}"),
    })
}

pub fn dictionary_attack_rules(
    target_hash_hex: &str,
    algo: &str,
    wordlist: &Path,
    max_suffix: u32,
) -> Result<CrackMetadata> {
    let target = hex::decode(target_hash_hex)
        .map_err(|err| LockKnifeError::message(format!("invalid target hash: {err}")))?;
    let words = read_wordlist(wordlist)?;
    let variant_cap = 5_u64
        .checked_mul(max_suffix as u64 + 1)
        .ok_or_else(|| LockKnifeError::message("max_suffix too large"))?;
    let candidate_space = (words.len() as u64)
        .checked_mul(variant_cap)
        .ok_or_else(|| LockKnifeError::message("candidate space too large"))?;

    let recovered_secret = words.into_par_iter().find_map_any(|word| {
        let variants = variants(&word);
        for variant in variants {
            if let Ok(digest) = digest_for_algo(algo, variant.as_bytes()) {
                if digest == target {
                    return Some(variant);
                }
            }
            for suffix in 0..=max_suffix {
                let candidate = format!("{variant}{suffix}");
                if let Ok(digest) = digest_for_algo(algo, candidate.as_bytes()) {
                    if digest == target {
                        return Some(candidate);
                    }
                }
            }
        }
        None
    });

    Ok(CrackMetadata {
        matched: recovered_secret.is_some(),
        recovered_secret,
        candidate_space,
        input_size: words.len() as u64,
        strategy: format!("offline-dictionary-rules-{algo}"),
    })
}

fn read_wordlist(path: &Path) -> Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    Ok(reader
        .lines()
        .map_while(|line| line.ok())
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect())
}

fn digest_for_algo(algo: &str, data: &[u8]) -> Result<Vec<u8>> {
    match algo {
        "sha1" => {
            let mut hasher = Sha1::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        "sha256" => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        "sha512" => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
        _ => Err(LockKnifeError::message(format!("unsupported algorithm: {algo}"))),
    }
}

fn variants(word: &str) -> Vec<String> {
    let base = word.trim();
    let mut out = vec![
        base.to_string(),
        base.to_lowercase(),
        base.to_uppercase(),
        capitalize(base),
        leetify(base),
    ];
    out.sort();
    out.dedup();
    out
}

fn capitalize(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => {
            let mut out = String::new();
            out.extend(first.to_uppercase());
            out.push_str(chars.as_str());
            out
        }
        None => String::new(),
    }
}

fn leetify(word: &str) -> String {
    word.chars()
        .map(|c| match c {
            'a' | 'A' => '@',
            'e' | 'E' => '3',
            'i' | 'I' => '1',
            'o' | 'O' => '0',
            's' | 'S' => '$',
            't' | 'T' => '7',
            _ => c,
        })
        .collect()
}
