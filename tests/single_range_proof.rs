
use rand::thread_rng;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use std::time::Instant;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_proof() {
        let n: u8 = 64; // Note that if !(n == 8 || n == 16 || n == 32 || n == 64), the code returns Err(ProofError::InvalidBitsize)!
        let v: u64 = 4294967295;
        println!(
            "A range proof statement \"{} < 2^{}\"",
            v, n
        );
        range_proof_helper(v, n);
    }


fn range_proof_helper(v: u64, n: u8) {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);

    //Prover's scope
    // 0. Create witness data
    let blinding = Scalar::random(&mut thread_rng());

    let start = Instant::now();
    // Create the proof
    let mut transcript = Transcript::new(b"SingleRangeProofTest");
    let (proof, committed_value) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        v,
        &blinding,
        n.into(),
    )
    .unwrap();

    println!(
        "\t proving time: {} ms",
        start.elapsed().as_millis() as u128
    );

    // Verifier's scope
    // Verify with the same customization label as above
    let start = Instant::now();
    let mut transcript = Transcript::new(b"SingleRangeProofTest");

    assert!(proof
        .verify_single(&bp_gens, &pc_gens, &mut transcript, &committed_value, n.into())
        .is_ok());

    println!(
        "\t verification time: {} ms",
        start.elapsed().as_millis() as u128
    );
}
}
