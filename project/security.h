#ifndef SECURITY_H
#define SECURITY_H
#pragma once

#include <openssl/evp.h>

#define SECRET_SIZE 32
#define IV_SIZE 16
#define MAC_SIZE 32

// libcrypto internal repr. of keys
extern EVP_PKEY* ec_priv_key; // Local private key
extern EVP_PKEY* ec_peer_public_key; // Public key of other host
extern EVP_PKEY* ec_ca_public_key; // Public key of certificate authority

// Loaded certificate
extern int cert_size;
extern char* certificate;

// Loaded public key byte repr.
extern int pub_key_size;
extern char* public_key;

// ECDH secret
extern char* secret;

// Key for encryption/decryption
extern char* enc_key;

// Key for message authentication
extern char* mac_key;

// From file, load DER formatted private key into `ec_priv_key`
void load_private_key(char* filename);

// From buffer, load DER formatted peer key into `ec_peer_public_key`
void load_peer_public_key(char* peer_key, size_t size);

// From file, load DER formatted certificate authority public key into `ec_ca_public_key`
void load_ca_public_key(char* filename);

// From file, load ECDSA signed certificate into buffer `certificate`
void load_certificate(char* filename);

// Generate private key from the NID_X9_62_prime256v1 elliptic curve
void generate_private_key();

// From private key (make sure to call `load_private_key` or
// `generate_private_key` first), derive public key point on elliptic curve
void derive_public_key();

// From private key (make sure to call `load_private_key` or
// `generate_private_key` first) and peer key (make sure to call
// `load_peer_public_key` first), generate ECDH shared secret
void derive_secret();

// Derive ENC key and MAC key using HKDF SHA-256
void derive_keys();

// Using private key (make sure to call `load_private_key` or
// `generate_private_key` first), sign a buffer by hashing it with SHA-256 then
// applying ECDSA
// Returns size of signature
size_t sign(char* data, size_t size, char* signature);

// Using a certain authority (typically `ec_peer_public_key` or
// `ec_ca_public_key`), verify the authenticity of an ECDSA signature
// Returns 1 if verified successfully, other values if not
int verify(char* data, size_t size, char* signature, size_t sig_size, EVP_PKEY* authority);

// Generate cryptographically secure random data
void generate_nonce(char* buf, int size);

// Encrypt data using derived shared secret (make sure to call `derive_secret`
// first). Uses AES-256-CBC with PKCS7 padding. Buffers `iv` and `cipher` will have
// the resulting initial vector and ciphertext. 
// Set `using_mac` to a non-zero value to use the `enc_key` for encryption
// Returns size of ciphertext
size_t encrypt_data(char *data, size_t size, char *iv, char *cipher, int using_mac);

// Decrypt data using derived shared secret (make sure to call `derive_secret`
// first). Uses AES-256-CBC with PKCS7 padding. Buffer `data` will have
// the resulting decrypted data. 
// Set `using_mac` to a non-zero value to use the `enc_key` for decryption
// Returns size of data
size_t decrypt_cipher(char *cipher, size_t size, char *iv, char *data, int using_mac);

// Using the MAC key, generate an HMAC SHA-256 digest of `data` and place it in the
// buffer `digest`. Digest will always be 32 bytes (since SHA-256).
void hmac(char* data, size_t size, char* digest);

// Clean up all buffers and keys
void clean_up();

#endif // SECURITY_H