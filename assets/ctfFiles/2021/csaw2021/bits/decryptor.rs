use sha2::{Sha256,Digest};
use aes::{Aes256,Aes256Ctr,NewBlockCipher,cipher::{FromBlockCipher,StreamCipher}};
use generic_array::GenericArray;
use rug::{
    Integer
};
use std::str;

fn encrypt_flag(shared: Integer) {
    let mut hasher = Sha256::new();
    hasher.update(shared.to_string());
    println!("{}", shared.to_string());
    let key = hasher.finalize();
    println!("{:02x}", key);
    let mut cipher = Aes256Ctr::from_block_cipher(
        Aes256::new_from_slice(&key.as_slice()).unwrap(),
        &GenericArray::clone_from_slice(&[0; 16])
        );
    //let mut flag = b"flag{this_is_a_test_flag}".to_vec();
    let mut flag :Vec <u8> = vec![173, 80, 249, 30, 70, 40, 34, 67, 20, 125, 37, 109, 34, 67, 195, 78, 56, 94, 166, 246, 85, 151, 17, 54, 11, 64, 104, 251, 35, 109, 235, 50, 113, 108, 125, 26, 73, 79, 63, 255, 190, 111, 102, 23, 19, 13, 18, 169, 175];
    cipher.apply_keystream(&mut flag);
    println!("{:?}", flag);
    println!("FLAG = {}", flag.iter().map(|c| format!("{:02x}", c)).collect::<String>());
}

fn main() {
    let s1 = "594807822095334741057051620171396964019351564890894203928169190126461806308549435025248323868458092982166978694503647098000456023924393502691705391685441611869539041261186566093550374349863029469388639761010988841288179860043880441953525279127769332238007038702727402475636786533812164271387985856187587";
    let int = s1.parse::<Integer>().unwrap();
    encrypt_flag(int)
    //FLAG = 666c61677b68747470733a2f2f7777772e796f75747562652e636f6d2f77617463683f763d75685443655a6173436d637d
    //b'flag{https://www.youtube.com/watch?v=uhTCeZasCmc}'
}

