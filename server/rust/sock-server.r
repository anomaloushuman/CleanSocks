#   Created by anomaloushuman - Patrick Garcia
#   Email - patrick@ubiquityglass.com
#   12/19/2024 - Sock Server v0.0.1

use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::net::{TcpListener, TcpStream};
use std::io::{ReadExt, WriteExt};
use std::fs::File;
use std::io;
use std::path::Path;
use openssl::ssl::{SslContext, SslMethod, SslVerifyMode};
use openssl::pkey::PKey;
use openssl::x509::X509;
use openssl::ssl::SslStreamExt;
use openssl::hash::MessageDigest;
use openssl::symm::{Crypter, Cipher};
use openssl::error::ErrorStackExt;

const SERVER_KEY: &str = "your-very-secure-key"; // Shared secret key for HMAC and encryption

fn main() {
    let listener = TcpListener::bind("0.0.0.0:9000").expect("Unable to bind");
    println!("Secure protocol server started on port 9000");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    handle_client(stream);
                });
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }
}

fn handle_client(stream: TcpStream) {
    println!("Client connected");

    // Handshake
    let _ = stream.write(b"HELLO CLIENT\r\n");
    let mut response = [0; 1024];
    stream.read(&mut response).expect("Failed to read");
    let response = String::from_utf8_lossy(&response);
    if response.trim() != "HELLO SERVER" {
        let _ = stream.write(b"ERROR: INVALID HANDSHAKE\r\n");
        return;
    }

    let _ = stream.write(b"HANDSHAKE COMPLETE\r\n");

    let mut data = [0; 2048];
    stream.read(&mut data).expect("Failed to read");
    let data = String::from_utf8_lossy(&data);
    let (hmac, encrypted_message) = data.split_once(':').expect("Invalid data format");

    // Verify HMAC
    if !verify_hmac(encrypted_message, hmac, SERVER_KEY) {
        let _ = stream.write(b"ERROR: INVALID MESSAGE\r\n");
        return;
    }

    // Decrypt the message
    let message = decrypt_message(encrypted_message, SERVER_KEY);
    println!("Received: {}", message);

    let response = format!("You sent: {}", message);
    let encrypted_response = encrypt_message(&response, SERVER_KEY);
    let response_hmac = generate_hmac(&encrypted_response, SERVER_KEY);

    let _ = stream.write(format!("{}:{}\r\n", response_hmac, encrypted_response).as_bytes());
}

fn encrypt_message(message: &str, key: &str) -> String {
    use openssl::symm::{encrypt, Cipher};
    let iv = openssl::rand::rand_bytes(16).expect("Failed to generate IV");
    let encrypted = encrypt(Cipher::aes_256_cbc(), key.as_bytes(), Some(&iv), message.as_bytes()).expect("Failed to encrypt");
    format!("{:?}", base64::encode(&[iv, encrypted].concat()))
}

fn decrypt_message(data: &str, key: &str) -> String {
    use openssl::symm::{decrypt, Cipher};
    let decoded = base64::decode(data).expect("Failed to decode");
    let iv = decoded.into_iter().take(16).collect::<Vec<u8>>();
    let encrypted = decoded.into_iter().skip(16).collect::<Vec<u8>>();
    let decrypted = decrypt(Cipher::aes_256_cbc(), key.as_bytes(), Some(&iv), &encrypted).expect("Failed to decrypt");
    String::from_utf8_lossy(&decrypted)
}

fn generate_hmac(data: &str, key: &str) -> String {
    use openssl::hash::hmac;
    let hmac = hmac(MessageDigest::sha256(), key.as_bytes(), data.as_bytes()).expect("Failed to generate HMAC");
    format!("{:?}", base64::encode(&hmac))
}

fn verify_hmac(data: &str, hmac: &str, key: &str) -> bool {
    let expected_hmac = generate_hmac(data, key);
    hmac == &expected_hmac
}