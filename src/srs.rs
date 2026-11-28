//! SRS v2 subset emitted by this compiler. Integer arrays are big endian,
//! counts use unsigned LEB128, and the rule stream is zlib-compressed.
use anyhow::{Context, Result, bail, ensure};
use flate2::{Compression, write::ZlibEncoder};
use ipnet::IpNet;
use serde_json::Value;
use std::{collections::VecDeque, io::Write};

fn count(bytes: &mut Vec<u8>, mut n: usize) {
    while n >= 128 {
        bytes.push((n as u8 & 127) | 128);
        n >>= 7;
    }
    bytes.push(n as u8);
}

fn mark(words: &mut Vec<u64>, i: usize) {
    words.resize(words.len().max(i / 64 + 1), 0);
    words[i / 64] |= 1 << (i % 64);
}

fn domains(out: &mut Vec<u8>, exact: &[Value], suffix: &[Value]) -> Result<()> {
    let mut keys = Vec::new();
    for (values, is_suffix) in [(exact, false), (suffix, true)] {
        for item in values {
            let name = item.as_str().context("invalid domain")?;
            ensure!(
                !name.is_empty() && name.is_ascii(),
                "expected normalized ASCII domain"
            );
            let mut key: Vec<_> = name.bytes().rev().collect();
            if is_suffix {
                key.push(if name.starts_with('.') { b'\r' } else { b'\n' });
            }
            keys.push(key);
        }
    }
    keys.sort();
    keys.dedup();
    let mut leaves = Vec::new();
    let mut bitmap = Vec::new();
    let mut labels = Vec::new();
    let mut queue = VecDeque::from([(0, keys.len(), 0)]);
    let mut node = 0;
    let mut bit = 0;
    while let Some((mut lo, hi, depth)) = queue.pop_front() {
        if keys[lo].len() == depth {
            mark(&mut leaves, node);
            lo += 1;
        }
        while lo < hi {
            let byte = keys[lo][depth];
            let width = keys[lo..hi].partition_point(|key| key[depth] == byte);
            queue.push_back((lo, lo + width, depth + 1));
            labels.push(byte);
            lo += width;
            bit += 1;
        }
        mark(&mut bitmap, bit);
        bit += 1;
        node += 1;
    }
    out.extend([2, 0]);
    for words in [leaves, bitmap] {
        count(out, words.len());
        for word in words {
            out.extend(word.to_be_bytes());
        }
    }
    count(out, labels.len());
    out.extend(labels);
    Ok(())
}

fn prefixes(out: &mut Vec<u8>, values: &[Value]) -> Result<()> {
    let mut ranges = Vec::new();
    for v in values {
        let cidr: IpNet = v.as_str().context("invalid CIDR")?.parse()?;
        let range = match cidr {
            IpNet::V4(n) => (
                4usize,
                u32::from(n.network()) as u128,
                u32::from(n.broadcast()) as u128,
            ),
            IpNet::V6(n) => (16, u128::from(n.network()), u128::from(n.broadcast())),
        };
        ranges.push(range);
    }
    ranges.sort_unstable();
    let mut merged: Vec<(usize, u128, u128)> = Vec::new();
    for (width, start, end) in ranges {
        if let Some(last) = merged.last_mut()
            && last.0 == width
            && start <= last.2.saturating_add(1)
        {
            last.2 = last.2.max(end);
        } else {
            merged.push((width, start, end));
        }
    }
    out.extend([6, 1]);
    out.extend((merged.len() as u64).to_be_bytes());
    for (width, start, end) in merged {
        for addr in [start, end] {
            out.push(width as u8);
            out.extend(&addr.to_be_bytes()[16 - width..]);
        }
    }
    Ok(())
}

fn rule(out: &mut Vec<u8>, value: &Value) -> Result<()> {
    if value["type"] == "logical" {
        let mode = match value["mode"].as_str() {
            Some("and") => 0,
            Some("or") => 1,
            _ => bail!("unknown logical mode"),
        };
        out.extend([1, mode]);
        let children = value["rules"].as_array().context("missing logical rules")?;
        count(out, children.len());
        for child in children {
            rule(out, child)?;
        }
    } else {
        out.push(0);
        let obj = value.as_object().context("expected rule")?;
        ensure!(
            obj.keys().all(|k| matches!(
                k.as_str(),
                "domain" | "domain_suffix" | "ip_cidr" | "invert"
            )),
            "unsupported generated SRS condition {value}"
        );
        let list = |k: &str| value[k].as_array().map(Vec::as_slice).unwrap_or_default();
        if !list("domain").is_empty() || !list("domain_suffix").is_empty() {
            domains(out, list("domain"), list("domain_suffix"))?;
        }
        if !list("ip_cidr").is_empty() {
            prefixes(out, list("ip_cidr"))?;
        }
        out.push(255);
    }
    out.push(value["invert"].as_bool().unwrap_or(false) as u8);
    Ok(())
}

pub fn encode(source: &Value) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    let rules = source["rules"].as_array().context("expected SRS rules")?;
    count(&mut payload, rules.len());
    for item in rules {
        rule(&mut payload, item)?;
    }
    let mut compressed = ZlibEncoder::new(b"SRS\x02".to_vec(), Compression::best());
    compressed.write_all(&payload)?;
    Ok(compressed.finish()?)
}
