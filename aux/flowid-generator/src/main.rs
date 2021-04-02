use rand::{seq::SliceRandom, Rng};
use std::collections::HashMap;

fn compute_entropy(previous: &[u16], value: u16, mask: u16) -> f64 {
    let mut values2counts: HashMap<u16, u16> = HashMap::new();
    for flowid in previous {
        *values2counts.entry(flowid & mask).or_insert(0) += 1;
    }
    *values2counts.entry(value & mask).or_insert(0) += 1;
    let total = previous.len() + 1;
    let entropy: f64 = values2counts
        .values()
        .filter(|&cnt| *cnt > 0u16)
        .fold(0.0, |acc, &cnt| {
            let p = (cnt as f64) / (total as f64);
            acc - p * p.log2()
        });
    entropy
}

// Let f1, f2, ..., fn be the flow identifiers generated for the
// first n probes.  We generate the new flow identifier fn+1 greedily
// bit-by-bit in random order.  The value of each bit is set such that it
// maximizes the Shannon entropy of the distribution of values seen over
// the n+1 identifiers, restricted to the bits considered so far, with ties
// broken randomly.  If the generated fn+1 repeats an earlier identifier,
// bits are randomly flipped until uniqueness is obtained.
fn generate_flow_id(previous: &[u16]) -> u16 {
    let mut rng = rand::thread_rng();

    if previous.is_empty() {
        return rng.gen_range(0, u16::MAX);
    }

    let mut value: u16 = 0;
    let mut mask: u16 = 0;
    let mut bit_order: [u8; 16] = [0; 16];

    for i in 0..16 {
        bit_order[i as usize] = i
    }
    bit_order.shuffle(&mut rng);

    for order in bit_order.iter() {
        let bitmask = 1u16 << order;
        mask |= bitmask;
        let entropy0 = compute_entropy(previous, value, mask);
        let entropy1 = compute_entropy(previous, value | bitmask, mask);
        if (entropy0 - entropy1).abs() < 1e-6 {
            value |= rng.gen_range(0, 2) * bitmask;
        } else if entropy0 < entropy1 {
            value |= bitmask;
        }
    }
    assert!(mask == u16::MAX);

    while previous.contains(&value) {
        let i = rng.gen_range(0, 16);
        let bitmask = 1u16 << i;
        value ^= bitmask;
    }

    value
}

fn main() -> Result<(), std::num::ParseIntError> {
    let args: Vec<String> = std::env::args().collect();
    let nids: u16 = args[1].parse::<u16>()?;
    let mut previous: Vec<u16> = Vec::with_capacity(nids as usize);
    for _ in 0..nids {
        let flowid: u16 = generate_flow_id(&previous);
        previous.push(flowid);
        println!("{}", flowid);
    }
    Ok(())
}

#[cfg(test)]
mod test;
