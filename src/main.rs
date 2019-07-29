#![forbid(unsafe_code)]



use rand::*;
use ring::agreement::{ECDH_P256,ECDH_P384,X25519};
use ring::aead::{CHACHA20_POLY1305,AES_128_GCM,AES_256_GCM};
use ring::digest::{Context, SHA256, SHA384, SHA512, SHA512_256};
use ring::hkdf::{HKDF_SHA256,HKDF_SHA384,HKDF_SHA512};
use ring::hmac::{HMAC_SHA256,HMAC_SHA384,HMAC_SHA512};
use ring::pbkdf2::{PBKDF2_HMAC_SHA256,PBKDF2_HMAC_SHA384,PBKDF2_HMAC_SHA512};
//use ring::rand as ringrand;
use data_encoding::BASE64;



fn test_aead(key : &[u8], data :&[u8], datalength : usize, algo: &'static ring::aead::Algorithm ) {

    // Ring uses the same input variable as output
    let mut in_out = data.to_vec();

    // The input/output variable need some space for a suffix
    for _ in 0..algo.tag_len() {
        in_out.push(0);
    }

    // Opening key used to decrypt data
    let unboud_key = ring::aead::UnboundKey::new(algo,key).unwrap();
    let less_safe_key = ring::aead::LessSafeKey::new(unboud_key);
    //Nonce::assume_unique_for_key(*nonce_byte),

    // Sealing key used to encrypt data
    //let sealing_key = SealingKey::new(&algo, key).unwrap();

    // Random nonce is first 12 bytes of a hash of the key
    let nonce_byte = &mut [0; 12];
    let mut context = Context::new(&SHA256);
    context.update(&key[..]);
    nonce_byte.copy_from_slice(&context.finish().as_ref()[0..12]);

    // Encrypt data into in_out variable
    ring::aead::LessSafeKey::seal_in_place_append_tag(
        &less_safe_key ,
        ring::aead::Nonce::assume_unique_for_key(*nonce_byte),
        ring::aead::Aad::empty(),
        &mut in_out
    )
    .unwrap();

    // println!("Encrypted data's size {}", output_size);

    let decrypted_data = ring::aead::LessSafeKey::open_in_place(
        &less_safe_key,
        ring::aead::Nonce::assume_unique_for_key(*nonce_byte),
        ring::aead::Aad::empty(),
        &mut in_out,
    )
    .unwrap();

    //println!("{}", BASE64.encode(&data[..]));
    //println!("{}", BASE64.encode(&decrypted_data[..datalength]));
    assert_eq!(data[..], decrypted_data[..datalength]);

}
fn test_agreement(key : &[u8], algo: &'static ring::agreement::Algorithm ) {
    //let rng = ringrand::SystemRandom::new();
    let rng = ring::test::rand::FixedSliceRandom { bytes: key};
    println!("Before Private key");
    let my_private_key = ring::agreement::EphemeralPrivateKey::generate(&algo, &rng).unwrap();

    // Make `my_public_key` a byte slice containing my public key. In a real
    // application, this would be sent to the peer in an encoded protocol
    // message.
    println!("Before Public key");
    let _my_public_key = my_private_key.compute_public_key().unwrap();

    let peer_private_key = ring::agreement::EphemeralPrivateKey::generate(&algo, &rng).unwrap();
    let peer_public_key =  peer_private_key.compute_public_key().unwrap();
    let peer_public_key = ring::agreement::UnparsedPublicKey::new(&algo, peer_public_key);

    // In a real application, the peer public key would be parsed out of a
    // protocol message. Here we just generate one.

    ring::agreement::agree_ephemeral(
        my_private_key,
        &peer_public_key,
        ring::error::Unspecified,
        |_key_material| {
            // In a real application, we'd apply a KDF to the key material and the
            // public keys (as recommended in RFC 7748) and then derive session
            // keys from the result. We omit all that here.
            Ok(())
        },
    ).unwrap();
}


fn test_digest(data :&[u8], aglo: &'static ring::digest::Algorithm ){
    let mut context = Context::new(aglo);
    context.update(data);
    context.finish();
}



fn test_hkdf(data :&[u8], key : &[u8],algo: &'static ring::hkdf::Algorithm ) {
    let salt  = ring::hkdf::Salt::new(*algo,key);
    let _prk = salt.extract(data);
    //let info: &[&[u8]];
    //prk.expand(&[&data], 5).unwrap().into();
//    let okm_item = ring::hkdf::Prk::expand(&prk, ;
}



fn test_hmac(key : &[u8], data :&[u8], algo: &'static ring::hmac::Algorithm ) {
        let key = ring::hmac::Key::new(*algo, key);
        let signature = ring::hmac::sign(&key, data);
        assert_eq!(true, ring::hmac::verify(&key, data, signature.as_ref()).is_ok());
    }

fn test_pbkdf2(data: &[u8], iterations: usize, algo: &'static ring::pbkdf2::Algorithm ) {
    let mut out = vec![0u8];
    let salt = &mut [0,16];
    let mut context = Context::new(&SHA256);
    context.update(&data[..]);
    salt.copy_from_slice(&context.finish().as_ref()[0..16]);
    let iterations = std::num::NonZeroU32::new((iterations % 100 )as u32).unwrap();
    ring::pbkdf2::derive(*algo, iterations , &salt[..], &data, &mut out);
    assert_eq!( ring::pbkdf2::verify(*algo, iterations, &salt[..], &data, &out),Ok(()));
}

fn main() {
    let mut rng = rand::thread_rng();

    let datalength: usize = rng.gen_range(0, 1000);
    //println!("Data lenght is {}", datalength);

    let mut content = Vec::new();
    for _ in 0..datalength {
        let value: u8 = rng.gen();
        content.push(value);
    }
    let data = content.as_ref();
    let key : &mut [u8] = &mut[0;32];
    let mut context = Context::new(&SHA256);
    context.update(&data);
    key.copy_from_slice(&context.finish().as_ref()[..]);
    println!("Data: {}", BASE64.encode(data));

    //println!("CHACHA20_POLY1305");
    test_aead(key,data,datalength,&CHACHA20_POLY1305);
    //Note: 128 bit key not 256 like the other two aeads
    test_aead(&key[0..16],data,datalength,&AES_128_GCM);
    //println!("AES_256_GCM");
    test_aead(key,data,datalength,&AES_256_GCM);
    println!("done aead");

    test_agreement(key,&ECDH_P256);
    test_agreement(key,&ECDH_P384);
    test_agreement(key,&X25519);
    println!("done agreement");

    test_digest(data,&SHA256);
    test_digest(data,&SHA384);
    test_digest(data,&SHA512);
    test_digest(data,&SHA512_256);
    println!("done digest");

    test_hkdf(data,key,&HKDF_SHA256);
    test_hkdf(data,key,&HKDF_SHA384);
    test_hkdf(data,key,&HKDF_SHA512);
    println!("done hkdf");

    test_hmac(data,key,&HMAC_SHA256);
    test_hmac(data,key,&HMAC_SHA384);
    test_hmac(data,key,&HMAC_SHA512);
    println!("done hmac");

    test_pbkdf2(data,datalength,&PBKDF2_HMAC_SHA256);
    test_pbkdf2(data,datalength,&PBKDF2_HMAC_SHA384);
    test_pbkdf2(data,datalength,&PBKDF2_HMAC_SHA512);
    println!("done pbkdf2");
}
