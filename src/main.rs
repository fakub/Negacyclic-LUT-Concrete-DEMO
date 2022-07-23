use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;

use bincode;

#[allow(unused_imports)]
use rayon::prelude::*;

use concrete_core::prelude::*;

pub const M3_C2_STP_FILE: &str = "./keys/m3c2.stp";

///
/// Goal of this DEMO:
///  * encrypt k-bit integer without any padding or carry buffer
///  * allow for addition of l independent samples (correctness of param choice?)
///  * evaluate custom LUT of 2^{k-1} entries (the remaining values consist of LUT's negacyclic extension)
///
fn main() -> Result<(), Box<dyn std::error::Error>> {

    // -------------------------------------------------------------------------
    //  Generate / load params & keys
    let path_m3c2  = Path::new(M3_C2_STP_FILE);
    let (params, _lwe_secret_key_after_ks, _glwe_secret_key, lwe_secret_key, key_switching_key, bootstrapping_key) = if !path_m3c2 .is_file() {
        println!("Generating new params & keys");
        let params = concrete_shortint::parameters::PARAM_MESSAGE_3_CARRY_2;
        let var_lwe = Variance(params.lwe_modular_std_dev.get_variance());
        let var_rlwe = Variance(params.glwe_modular_std_dev.get_variance());
        let mut engine = CoreEngine::new(())?;

        // client keys
        let lwe_secret_key_after_ks: LweSecretKey64 = engine.create_lwe_secret_key(params.lwe_dimension)?;
        let glwe_secret_key: GlweSecretKey64 = engine.create_glwe_secret_key(params.glwe_dimension, params.polynomial_size)?;
        let lwe_secret_key: LweSecretKey64 = engine.transmute_glwe_secret_key_to_lwe_secret_key(glwe_secret_key.clone())?;

        // server keys
        let key_switching_key: LweKeyswitchKey64 = engine.create_lwe_keyswitch_key(
            &lwe_secret_key,
            &lwe_secret_key_after_ks,
            params.ks_level,
            params.ks_base_log,
            var_lwe,
        )?;
        let bootstrapping_key: FourierLweBootstrapKey64 = engine.create_lwe_bootstrap_key(
            &lwe_secret_key_after_ks,
            &glwe_secret_key,
            params.pbs_base_log,
            params.pbs_level,
            var_rlwe,
        )?;

        println!("Exporting new params & keys");
        let stp_file = File::create(path_m3c2).map(BufWriter::new)?;
        bincode::serialize_into(stp_file, &(&params, &lwe_secret_key_after_ks, &glwe_secret_key, &lwe_secret_key, &key_switching_key, &bootstrapping_key))?;

        (params, lwe_secret_key_after_ks, glwe_secret_key, lwe_secret_key, key_switching_key, bootstrapping_key)
    } else {
        println!("Loading saved params & keys");
        let stp_file = File::open(path_m3c2).map(BufReader::new)?;
        bincode::deserialize_from(stp_file)?
    };

    // create fresh engine (cannot be serialized)
    let mut engine = CoreEngine::new(())?;
    let var_lwe = Variance(params.lwe_modular_std_dev.get_variance());
    // let var_rlwe = Variance(params.glwe_modular_std_dev.get_variance());

    // -------------------------------------------------------------------------
    //  Messages
    let mv = vec![23, 15];

    // encoding (custom)
    let bit_precision = 5;
    let delta = 1 << (64 - bit_precision);
    let mut enc_mv = Vec::new();
        println!("\nMessages & Encoding:");
    for mi in mv {
        enc_mv.push(mi * delta);
        println!("mi = {} encoded as {:#066b}", mi, mi * delta);
    }

    // plaintext
    let mut pv = Vec::new();
    for enc_mi in enc_mv {
        let pi: Plaintext64 = engine.create_plaintext(&enc_mi)?;
        pv.push(pi);
    }

    // -------------------------------------------------------------------------
    //  Encryption
    let mut cv = Vec::new();
    for pi in pv {
        let ci: LweCiphertext64 = engine.encrypt_lwe_ciphertext(&lwe_secret_key, &pi, var_lwe)?;
        cv.push(ci);
    }

    // -------------------------------------------------------------------------
    //  Homomorphic addition: csum <- c0 + c1
    let mut csum = cv[0].clone();
    engine.fuse_add_lwe_ciphertext(&mut csum, &cv[1])?;

    // -------------------------------------------------------------------------
    //  Create PBS accumulator
    //~ let func = |value: u64| {value.pow(5) % (1 << bit_precision) as u64};
    let func = |value: u64| {(value - 2) % (1 << bit_precision) as u64};
    let accumulator = create_accum(func, &bootstrapping_key, bit_precision, &mut engine)?;

    // -------------------------------------------------------------------------
    //  Run PBS
    //
    //TODO parallel iterator fails to compile
    for ci in cv.iter_mut() {
    //~ for ci in cv.par_iter_mut() {
        // init buffer
        let zero_plaintext = engine.create_plaintext(&0_u64)?;
        let mut buffer_lwe_after_pbs = engine.trivially_encrypt_lwe_ciphertext(
            key_switching_key.output_lwe_dimension().to_lwe_size(),
            &zero_plaintext,
        )?;
        // Compute a key switch
        engine.discard_keyswitch_lwe_ciphertext(
            &mut buffer_lwe_after_pbs,
            ci,
            &key_switching_key,
        )?;
        // Compute a bootstrap
        engine.discard_bootstrap_lwe_ciphertext(
            ci,
            &buffer_lwe_after_pbs,
            &accumulator,
            &bootstrapping_key,
        )?;
    }

    // -------------------------------------------------------------------------
    //  Decrypt
    let mut pv_res = Vec::new();
    for ci in cv {
        let pi_res: Plaintext64 = engine.decrypt_lwe_ciphertext(&lwe_secret_key, &ci)?;
        pv_res.push(pi_res);
    }
    let psum_res: Plaintext64 = engine.decrypt_lwe_ciphertext(&lwe_secret_key, &csum)?;

    let mut mv_res = Vec::new();
    for pi_res in pv_res {
        let mut enc_mi_res = 0_u64;
        engine.discard_retrieve_plaintext(&mut enc_mi_res, &pi_res)?;
        mv_res.push(enc_mi_res);
    }
    let mut enc_msum_res: u64 = 0;
    engine.discard_retrieve_plaintext(&mut enc_msum_res, &psum_res)?;

    // -------------------------------------------------------------------------
    //  Print results
    println!("\nDecrypted results (still encoded):");
    for mi_res in mv_res {
        println!("mi encoded  {:#066b}", mi_res);
    }
    println!("sum encoded {:#066b}", enc_msum_res);

    println!("Bye!");

    Ok(())
}

fn create_accum<F>(
    func: F,
    bootstrapping_key: &FourierLweBootstrapKey64,
    bit_precision: usize,
    engine: &mut CoreEngine,
) -> Result<GlweCiphertext64, Box<dyn std::error::Error>>
where F: Fn(u64) -> u64 {
    let delta = 1 << (64 - bit_precision);
    let mut accumulator_u64 = vec![0_u64; bootstrapping_key.polynomial_size().0];
    let modulus_sup = 1 << (bit_precision - 1);   // half of values is to be set .. 16
    let box_size = bootstrapping_key.polynomial_size().0 / modulus_sup;
    let half_box_size = box_size / 2;
    // fill accumulator
    for i in 0..modulus_sup {
        let index = i as usize * box_size;
        accumulator_u64[index..index + box_size]
            .iter_mut()
            .for_each(|a| *a = func(i as u64) * delta);
    }
    // Negate the first half_box_size coefficients
    for a_i in accumulator_u64[0..half_box_size].iter_mut() {
        *a_i = (*a_i).wrapping_neg();
    }
    // Rotate the accumulator
    accumulator_u64.rotate_left(half_box_size);
    // init accumulator as GLWE
    let accumulator_plaintext = engine.create_plaintext_vector(&accumulator_u64)?;

    let accumulator = engine.trivially_encrypt_glwe_ciphertext(
        bootstrapping_key.glwe_dimension().to_glwe_size(),
        &accumulator_plaintext,
    )?;

    Ok(accumulator)
}
