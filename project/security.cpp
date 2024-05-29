#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdio.h>
#include "security.h"

#include <errno.h>

EVP_PKEY* ec_priv_key = NULL;
EVP_PKEY* ec_peer_public_key = NULL;
EVP_PKEY* ec_ca_public_key = NULL; 

int cert_size = 0;
char* certificate = NULL;
int pub_key_size = 0;
char* public_key = NULL;
char* secret = NULL;
char* enc_key = NULL;
char* mac_key = NULL;

void load_private_key(char* filename) {
    FILE* fp = fopen(filename, "r");
    ec_priv_key = d2i_PrivateKey_fp(fp, NULL);
    fclose(fp);
}

void load_peer_public_key(char* peer_key, size_t size) {
    BIO* bio = BIO_new_mem_buf(peer_key, size);
    ec_peer_public_key = d2i_PUBKEY_bio(bio, NULL);
    BIO_free(bio);
}

void load_ca_public_key(char* filename) {
    FILE* fp = fopen(filename, "r");
    ec_ca_public_key = d2i_PUBKEY_fp(fp, NULL);
    fclose(fp);
}

void load_certificate(char* filename) {
    FILE* fp = fopen(filename, "r");
    char* cert;

    fseek(fp, 0, SEEK_END);
    cert_size = ftell(fp);
    cert = (char*) malloc(cert_size);
    fseek(fp, 0, 0);
    fread(cert, cert_size, 1, fp);
    certificate = cert;
    fclose(fp);
}

void generate_private_key() {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    EVP_PKEY_keygen(pctx, &ec_priv_key);

    EVP_PKEY_CTX_free(pctx);
}

void derive_public_key() {
    pub_key_size = i2d_PUBKEY(ec_priv_key, (unsigned char**) &public_key);
}

void derive_secret() {
    size_t sec_size = SECRET_SIZE;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(ec_priv_key, NULL);

    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, ec_peer_public_key);
    secret = (char*) malloc(sec_size);
    EVP_PKEY_derive(ctx, (unsigned char*) secret, &sec_size);

    EVP_PKEY_CTX_free(ctx);
}

void derive_keys() {
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx;
    OSSL_PARAM params[4];
    
    kdf = EVP_KDF_fetch(NULL, "hkdf", NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf); 

    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char*) "sha256", (size_t) 7);
    params[1] = OSSL_PARAM_construct_octet_string("key", (char*) secret, (size_t) SECRET_SIZE);
    params[2] = OSSL_PARAM_construct_octet_string("info", (char*) "enc", (size_t) 3);
    params[3] = OSSL_PARAM_construct_end();
    EVP_KDF_CTX_set_params(kctx, params);

    enc_key = (char*) malloc(SECRET_SIZE);
    EVP_KDF_derive(kctx, (unsigned char*) enc_key, SECRET_SIZE, NULL);

    params[2] = OSSL_PARAM_construct_octet_string("info", (char*) "mac", (size_t) 3);
    EVP_KDF_CTX_set_params(kctx, params);

    mac_key = (char*) malloc(SECRET_SIZE);
    EVP_KDF_derive(kctx, (unsigned char*) mac_key, SECRET_SIZE, NULL);

    EVP_KDF_CTX_free(kctx);
}

size_t sign(char* data, size_t size, char* signature) {
    size_t sig_size = 255;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, ec_priv_key);
    EVP_DigestSignUpdate(mdctx, data, size);
    EVP_DigestSignFinal(mdctx, (unsigned char*) signature, &sig_size);

    EVP_MD_CTX_free(mdctx);
    return sig_size;
}

int verify(char* data, size_t size, char* signature, size_t sig_size, EVP_PKEY* authority) {    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        perror("error1");
        return 0; 
    }
    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, authority) != 1) {
        perror("error2");
        fprintf(stderr, "%d", errno);
        EVP_MD_CTX_free(mdctx);
        return 0; 
    }
    if (EVP_DigestVerifyUpdate(mdctx, data, size) != 1) {
        // Handle error: failed to update verification context
        perror("error3");
        EVP_MD_CTX_free(mdctx);
        return 0;
    }
    int verification_result = EVP_DigestVerifyFinal(mdctx, (unsigned char *)signature, sig_size);
    EVP_MD_CTX_free(mdctx);
    return verification_result;
}


void generate_nonce(char* buf, int size) {
    RAND_bytes((unsigned char*) buf, size);
}

size_t encrypt_data(char *data, size_t size, char *iv, char *cipher, int using_mac) {
    int cipher_size;
    int padding_size;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    generate_nonce(iv, IV_SIZE);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char*) (using_mac ? enc_key : secret), (const unsigned char*) iv);
    EVP_EncryptUpdate(ctx, (unsigned char*) cipher, &cipher_size, (const unsigned char*) data, size);
    EVP_EncryptFinal_ex(ctx, (unsigned char*) cipher + cipher_size, &padding_size);

    EVP_CIPHER_CTX_free(ctx);

    return cipher_size + padding_size;
}

size_t decrypt_cipher(char *cipher, size_t size, char *iv, char *data, int using_mac) {
    // TODO: Implement this yourself! Hint: it's very similar to `encrypt_data`.
    // See https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
    int len;
    int plaintext_len;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char*) (using_mac ? enc_key : secret), (const unsigned char*) iv);
    EVP_DecryptUpdate(ctx, (unsigned char*) data, &len, (const unsigned char*) cipher, size);
    EVP_DecryptFinal_ex(ctx, (unsigned char*)data + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

void hmac(char* data, size_t size, char* digest) {
    unsigned int mac_size = MAC_SIZE;
    HMAC(EVP_sha256(), mac_key, SECRET_SIZE, (const unsigned char*) data, size, (unsigned char*) digest, &mac_size);
}

void clean_up() {
    if (ec_priv_key) EVP_PKEY_free(ec_priv_key);
    if (ec_peer_public_key) EVP_PKEY_free(ec_peer_public_key);
    if (ec_ca_public_key) EVP_PKEY_free(ec_ca_public_key);
    if (certificate) free(certificate);
    if (public_key) free(public_key);
    if (secret) free(secret);
    if (enc_key) free(enc_key);
    if (mac_key) free(mac_key);
}