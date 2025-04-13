# HiAE - High throughput Authenticated Encryption

This is a performant and feature complete pure-rust implementation of HiAE.

Currently this is built using an [unstable version of RustCrypto traits](https://github.com/RustCrypto/traits/tree/3620aba4f1e81e506b46a5f88c47f7ee3a7b87e0).

## Features

### Authenticated Encryption with Additional Data (AEAD)

`HiAe` offers authenticated encryption with 256 bit keys and 128 bit nonces.

### Message Authentication Codes (MAC)

`HiAeMac` offers message authentication with 256 bit keys and 128 bit nonces.

## Usage

### AEAD

```rust
use hiae_cl::{aead::{Aead, AeadCore, KeyInit}, HiAe};

let key = HiAe::generate_key().unwrap();
let cipher = HiAe::new(&key);
let nonce = HiAe::generate_nonce().unwrap();
let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref()).unwrap();
let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
assert_eq!(&plaintext, b"plaintext message");
```

### MAC

```rust
use hiae_cl::{digest::Mac, digest::crypto_common::KeyIvInit, HiAeMac};

let key = HiAeMac::generate_key().unwrap();
let iv = HiAeMac::generate_iv().unwrap();

let mut mac = HiAeMac::new(&key, &iv);
mac.update(b"plaintext message".as_ref());
let tag = mac.finalize().into_bytes();

let mut mac = HiAeMac::new(&key, &iv);
mac.update(b"plaintext message".as_ref());
mac.verify(&tag).unwrap();
```

### Stream

```rust
use hiae_cl::{cipher::{KeyIvInit, StreamCipher}, high::HiAeStream};

let key = HiAeStream::generate_key().unwrap();
let iv = HiAeStream::generate_iv().unwrap();

let mut buffer = *b"plaintext message";

let mut cipher = HiAeStream::new(&key, &iv);
cipher.apply_keystream(&mut buffer);

let mut cipher = HiAeStream::new(&key, &iv);
cipher.apply_keystream(&mut buffer);

assert_eq!(&buffer, b"plaintext message");
```
