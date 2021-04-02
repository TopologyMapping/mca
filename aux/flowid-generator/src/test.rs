use super::{compute_entropy, generate_flow_id};

#[test]
fn test_generate_flow_id_bits() {
    let previous: Vec<u16> = vec![1, 2, 4];
    let flowid = generate_flow_id(&previous);
    assert!((flowid & 0x7) == 0);
}

#[test]
fn test_generate_flow_id_max() {
    let mut previous: Vec<u16> = Vec::with_capacity(u16::MAX as usize);
    for i in 0..u16::MAX {
        previous.push(i);
    }
    let flowid = generate_flow_id(&previous);
    assert!(flowid == u16::MAX);
}

#[test]
fn test_compute_entropy() {
    let previous: Vec<u16> = vec![1];
    let value: u16 = 0;
    let mask: u16 = 1;
    let entropy = compute_entropy(&previous, value, mask);
    assert!((entropy - 1.0).abs() < 1e-6);

    let previous: Vec<u16> = vec![0];
    let value: u16 = 0;
    let mask: u16 = 1;
    let entropy = compute_entropy(&previous, value, mask);
    assert!(entropy.abs() < 1e-6);

    let previous: Vec<u16> = vec![1];
    let value: u16 = 2;
    let mask: u16 = 3;
    let entropy = compute_entropy(&previous, value, mask);
    assert!((entropy - 1.0).abs() < 1e-6);

    let previous: Vec<u16> = vec![1, 2, 4, 8];
    let value: u16 = 16;
    let mask: u16 = 0x1f;
    let entropy = compute_entropy(&previous, value, mask);
    let truth = -1.0 * 0.2f64.log2();
    assert!((entropy - truth).abs() < 1e-6);

    let previous: Vec<u16> = vec![1, 9];
    let value: u16 = 2;
    let mask: u16 = 0x3;
    let entropy = compute_entropy(&previous, value, mask);
    let truth: f64 =
        -1.0 * ((2.0 / 3.0) * (2.0f64 / 3.0).log2() + (1.0 / 3.0) * (1.0f64 / 3.0).log2());
    println!("{} {}", entropy, truth);
    assert!((entropy - truth).abs() < 1e-6);
}
