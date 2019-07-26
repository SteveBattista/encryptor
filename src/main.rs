#![forbid(unsafe_code)]
use rand::prelude::*;
use ring::aead::*;
use ring::digest::{Context, SHA256};
//use data_encoding::BASE64;

fn main() {
    let mut rng = rand::thread_rng();

    let datalength : u32 = rng.gen_range(0, 1000000);
    println!("Data lenght is {}",datalength );

    let mut content = Vec::new();
    for _ in 0..datalength {
        let value: u8 = rng.gen();
        content.push(value);
    }
    let key = &mut [0; 32];
    let mut context = Context::new(&SHA256);
    context.update(&content);
    key.copy_from_slice(&context.finish().as_ref()[..]);
    // Ring uses the same input variable as output
    let mut in_out = content.clone();
    println!("Cloned content");
    // The input/output variable need some space for a suffix
    for _ in 0..AES_256_GCM.tag_len() {
        in_out.push(0);
    }
    //println!("expanded in_out");

    // Opening key used to decrypt data
    let opening_key = OpeningKey::new(&AES_256_GCM, key).unwrap();
    //println!("made OpeningKey");

    // Sealing key used to encrypt data
    let sealing_key = SealingKey::new(&AES_256_GCM, key).unwrap();
    //println!("Created Keys");
    // Random nonce is first 12 bytes of a hash of the key
    let nonce_byte = &mut [0; 12];
    let mut context = Context::new(&SHA256);
    context.update(&key[..]);
    nonce_byte.copy_from_slice(&context.finish().as_ref()[0..12]);

    // Encrypt data into in_out variable
    let _output_size = seal_in_place(
        &sealing_key,
        Nonce::assume_unique_for_key(*nonce_byte),
        Aad::empty(),
        &mut in_out,
        AES_256_GCM.tag_len(),
    )
    .unwrap();

     //println!("Encrypted data's size {}", output_size);

    let decrypted_data = open_in_place(
        &opening_key,
        Nonce::assume_unique_for_key(*nonce_byte),
        Aad::empty(),
        0,
        &mut in_out,
    )
    .unwrap();

    //println!("{}", BASE64.encode(content.as_ref()));
    assert_eq!(content, decrypted_data);
}
