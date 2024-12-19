#   Created by anomaloushuman - Patrick Garcia
#   Email - patrick@ubiquityglass.com
#   12/19/2024 - Sock Server v0.0.1

use std::io::{Read, Write};
use std::net::TcpStream;
use openssl::ssl::{SslConnector, SslMethod};
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::rand::rand_bytes;
use openssl::hash::{Hasher, MessageDigest};
use base64::{encode, decode};

fn main() {
    let client_key = b"your-very-secure-key"; // Shared secret key for HMAC and encryption

    // Create an SSL connector
    let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();
    let stream = TcpStream::connect("localhost:9000").unwrap();
    let mut stream = connector.connect("localhost", stream).unwrap();

    // Handshake
    let mut response = [0; 1024];
    stream.read(&mut response).unwrap();
    let response = String::from_utf8_lossy(&response).trim().to_string();
    if response != "HELLO CLIENT" {
        panic!("Handshake failed: {}", response);
    }

    stream.write_all(b"HELLO SERVER\r\n").unwrap();
    stream.read(&mut response).unwrap();
    let response = String::from_utf8_lossy(&response).trim().to_string();
    if response != "HANDSHAKE COMPLETE" {
        panic!("Handshake failed: {}", response);
    }

    println!("Connected to server");

    // Send a secure message
    let message = "This is a test message";
    let encrypted_message = encrypt_message(message, client_key);
    let hmac = generate_hmac(&encrypted_message, client_key);

    stream.write_all(format!("{}:{}\r\n", hmac, encrypted_message).as_bytes()).unwrap();

    // Receive and decrypt server response
    let mut response = [0; 2048];
    stream.read(&mut response).unwrap();
    let response = String::from_utf8_lossy(&response).trim().to_string();
    let parts: Vec<&str> = response.split(':').collect();
    let (hmac, encrypted_response) = (parts[0], parts[1]);

    if !verify_hmac(encrypted_response, hmac, client_key) {
        panic!("Invalid server response");
    }

    let decrypted_response = decrypt_message(encrypted_response, client_key);
    println!("Server response: {}", decrypted_response);
}

fn encrypt_message(message: &str, key: &[u8]) -> String {
    let iv = rand_bytes(16).unwrap();
    let mut crypter = Crypter::new(Cipher::aes_256_cbc(), Mode::Encrypt, key, Some(&iv)).unwrap();
    let mut ciphertext = vec![0; message.len() + Cipher::aes_256_cbc().block_size()];
    let count = crypter.update(message.as_bytes(), &mut ciphertext).unwrap();
    let rest = crypter.finalize(&mut ciphertext[count..]).unwrap();
    ciphertext.truncate(count + rest);
    encode(&[&iv[..], &ciphertext[..]].concat())
}

fn decrypt_message(data: &str, key: &[u8]) -> String {
    let data = decode(data).unwrap();
    let (iv, encrypted) = data.split_at(16);
    let mut crypter = Crypter::new(Cipher::aes_256_cbc(), Mode::Decrypt, key, Some(iv)).unwrap();
    let mut decrypted = vec![0; encrypted.len() + Cipher::aes_256_cbc().block_size()];
    let count = crypter.update(encrypted, &mut decrypted).unwrap();
    let rest = crypter.finalize(&mut decrypted[count..]).unwrap();
    decrypted.truncate(count + rest);
    String::from_utf8(decrypted).unwrap()
}

fn generate_hmac(data: &str, key: &[u8]) -> String {
    let mut hasher = Hasher::new(MessageDigest::sha256()).unwrap();
    hasher.update(data.as_bytes()).unwrap();
    hasher.update(key).unwrap();
    encode(hasher.finish().unwrap())
}

fn verify_hmac(data: &str, hmac: &str, key: &[u8]) -> bool {
    let calculated_hmac = generate_hmac(data, key);
    calculated_hmac == hmac
}
