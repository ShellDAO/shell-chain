//! Complete, bounded, public ML-DSA-65 signature verification by STARKs.
//!
//! Every mathematical/hash step is verified by its component certificate. This
//! verifier routes authenticated outputs; it never calls a native signature,
//! SHAKE, NTT, sampling, Decompose, UseHint or norm implementation. It supports
//! the FIPS 204 pure signature interface with an empty context only.

use crate::{
    mldsa_challenge::{verify_challenge, ChallengeProof},
    mldsa_decode::{verify_signature_decode, SignatureDecodeProof},
    mldsa_equation::{verify_equation, EquationInputs, EquationProof},
    mldsa_finish::{verify_finish, FinishInputs, FinishProof},
    mldsa_inverse::{verify_inverse_ntt, InverseNttProof},
    mldsa_key::{verify_public_key_decode, PublicKeyDecodeProof},
    mldsa_matrix::{verify_matrix, MatrixProof},
    mldsa_ntt::{verify_ntt, NttProof, NTT_MODULUS},
    shake_sponge::{verify_shake, ShakeKind, ShakeProof},
};
use serde::{Deserialize, Serialize};

/// The mu input includes 64-byte tr and two empty-context framing bytes.
/// This development bound inherits the component SHAKE input bound of 4096.
pub const MAX_MESSAGE_BYTES: usize = 4030;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EquationPipeline {
    pub key: PublicKeyDecodeProof,
    pub signature: SignatureDecodeProof,
    pub matrix: MatrixProof,
    pub challenge: ChallengeProof,
    pub z_ntt: Vec<NttProof>,
    pub t1_ntt: Vec<NttProof>,
    pub c_ntt: NttProof,
    pub equation: EquationProof,
    pub inverse: Vec<InverseNttProof>,
}

/// A token can only be obtained by cryptographically checking the full equation
/// pipeline. It permits a producer to verify the expensive prefix once, then
/// generate and verify the completion without repeating the matrix checks.
pub struct VerifiedEquation {
    public_key: Vec<u8>,
    challenge_seed: Vec<u8>,
    finish: FinishInputs,
}
impl VerifiedEquation {
    pub fn finish_inputs(&self) -> &FinishInputs {
        &self.finish
    }
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    pub fn challenge_seed(&self) -> &[u8] {
        &self.challenge_seed
    }
}

fn array(values: &[u32]) -> Result<[u32; 256], String> {
    values
        .try_into()
        .map_err(|_| "expected 256 coefficients".into())
}
fn last(p: &NttProof) -> Result<[u32; 256], String> {
    array(p.stages.last().ok_or("missing NTT endpoint")?)
}

/// Authenticate raw pk/signature and prove the entire equation and inverse.
/// The expected key and signature must come from the caller's statement.
pub fn verify_equation_pipeline(
    p: &EquationPipeline,
    expected_key: &[u8],
    expected_signature: &[u8],
) -> Result<VerifiedEquation, String> {
    if expected_key.len() != 1952
        || expected_signature.len() != 3309
        || p.z_ntt.len() != 5
        || p.t1_ntt.len() != 6
        || p.inverse.len() != 6
    {
        return Err("invalid ML-DSA-65 equation pipeline shape".into());
    }
    verify_public_key_decode(&p.key, expected_key).map_err(|e| format!("public key: {e}"))?;
    verify_signature_decode(&p.signature, expected_signature)
        .map_err(|e| format!("signature encoding: {e}"))?;
    let matrix: Vec<_> = p
        .matrix
        .polynomials
        .iter()
        .map(|v| v.coefficients.clone())
        .collect();
    // A polynomial's claimed output is not trusted: verify_matrix proves every
    // byte of SHAKE128(rho || column || row) and every rejection decision.
    verify_matrix(&p.matrix, &p.key.decoded.rho, &matrix).map_err(|e| format!("matrix: {e}"))?;
    let c = p
        .challenge
        .challenge()
        .ok_or("missing challenge endpoint")?;
    verify_challenge(&p.challenge, &p.signature.decoded.challenge, c)
        .map_err(|e| format!("challenge: {e}"))?;
    let c: Vec<_> = c
        .iter()
        .map(|&v| match v {
            -1 => Ok(NTT_MODULUS - 1),
            0 => Ok(0),
            1 => Ok(1),
            _ => Err("invalid challenge residue"),
        })
        .collect::<Result<_, _>>()?;
    let mut z_ntt = Vec::with_capacity(5);
    for (i, proof) in p.z_ntt.iter().enumerate() {
        let output = last(proof)?;
        verify_ntt(proof, &array(&p.signature.decoded.z[i])?, &output)
            .map_err(|e| format!("z NTT {i}: {e}"))?;
        z_ntt.push(output.to_vec());
    }
    let mut t1_scaled_ntt = Vec::with_capacity(6);
    for (i, proof) in p.t1_ntt.iter().enumerate() {
        // Public fixed scaling of already authenticated ten-bit coefficients.
        let input: Vec<_> = p.key.decoded.t1[i]
            .iter()
            .map(|&v| u32::from(v) * 8192)
            .collect();
        let output = last(proof)?;
        verify_ntt(proof, &array(&input)?, &output).map_err(|e| format!("t1 NTT {i}: {e}"))?;
        t1_scaled_ntt.push(output.to_vec());
    }
    let challenge_ntt = last(&p.c_ntt)?;
    verify_ntt(&p.c_ntt, &array(&c)?, &challenge_ntt).map_err(|e| format!("challenge NTT: {e}"))?;
    let inputs = EquationInputs {
        matrix_ntt: matrix,
        z_ntt,
        t1_scaled_ntt,
        challenge_ntt: challenge_ntt.to_vec(),
    };
    verify_equation(&p.equation, &inputs, &p.equation.output)
        .map_err(|e| format!("equation: {e}"))?;
    let mut w_approx = Vec::with_capacity(6);
    for (i, proof) in p.inverse.iter().enumerate() {
        let output = array(
            proof
                .forward
                .stages
                .first()
                .ok_or("missing inverse endpoint")?,
        )?;
        verify_inverse_ntt(proof, &array(&p.equation.output[i])?, &output)
            .map_err(|e| format!("inverse NTT {i}: {e}"))?;
        w_approx.push(output.to_vec());
    }
    Ok(VerifiedEquation {
        public_key: expected_key.to_vec(),
        challenge_seed: p.signature.decoded.challenge.clone(),
        finish: FinishInputs {
            w_approx,
            hints: p.signature.decoded.hints.clone(),
            z: p.signature.decoded.z.clone(),
        },
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletionProof {
    pub finish: FinishProof,
    pub tr: ShakeProof,
    pub mu: ShakeProof,
    pub commitment: ShakeProof,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mldsa65VerificationProof {
    pub version: u8,
    pub equation: EquationPipeline,
    pub completion: CompletionProof,
}

/// Verify all remaining predicates against a token produced by actual prefix
/// verification. The caller supplies the message, never a trusted hash.
pub fn verify_completion(
    token: &VerifiedEquation,
    expected_message: &[u8],
    p: &CompletionProof,
) -> Result<(), String> {
    if expected_message.len() > MAX_MESSAGE_BYTES
        || p.tr.output.len() != 64
        || p.mu.output.len() != 64
        || p.commitment.output.len() != 48
    {
        return Err("unsupported message length or hash output size".into());
    }
    verify_finish(&p.finish, &token.finish, &p.finish.w1, &p.finish.encoded)
        .map_err(|e| format!("finish constraints: {e}"))?;
    verify_shake(&p.tr, ShakeKind::Shake256, &token.public_key, &p.tr.output)
        .map_err(|e| format!("tr hash: {e}"))?;
    let mut mu_input = p.tr.output.clone();
    mu_input.extend_from_slice(&[0, 0]);
    mu_input.extend_from_slice(expected_message);
    verify_shake(&p.mu, ShakeKind::Shake256, &mu_input, &p.mu.output)
        .map_err(|e| format!("mu hash: {e}"))?;
    let mut input = p.mu.output.clone();
    input.extend_from_slice(&p.finish.encoded);
    // Verify against the authenticated original c-tilde, not the certificate's
    // own output. A valid computation with a different hash must be rejected.
    verify_shake(
        &p.commitment,
        ShakeKind::Shake256,
        &input,
        &token.challenge_seed,
    )
    .map_err(|e| format!("final commitment: {e}"))
}

/// Verify a complete pure ML-DSA-65 signature with an empty context and a
/// bounded message, entirely via the linked component STARK certificates.
/// Public states are large development certificates, not a private/recursive
/// node settlement carrier. No default or network activation is implied.
pub fn verify_mldsa65(
    proof: &Mldsa65VerificationProof,
    expected_key: &[u8],
    expected_message: &[u8],
    expected_signature: &[u8],
) -> Result<(), String> {
    if proof.version != 1 || expected_message.len() > MAX_MESSAGE_BYTES {
        return Err("unsupported signature proof version or message length".into());
    }
    let token = verify_equation_pipeline(&proof.equation, expected_key, expected_signature)?;
    verify_completion(&token, expected_message, &proof.completion)
}
