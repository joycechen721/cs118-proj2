#include <unistd.h>
#include <stdio.h>

#include "security.h"

int main() {
    /* Server side */

    // Load server private key from file
    load_private_key("../keys/priv_key.bin");

    // Load client public key (typically over the network)
    int size;
    FILE* fp = fopen("../keys/client_pub_key.bin", "r");
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    char der[size];
    fseek(fp, 0, 0);
    fread(der, size, 1, fp);
    load_peer_public_key(der, size);

    // Derive ECDH secret
    derive_secret();

    // Derive ENC and MAC keys
    derive_keys();

    printf("Encryption key: %.*s\n", SECRET_SIZE, enc_key);
    printf("Authentication key: %.*s\n", SECRET_SIZE, mac_key);

    // HMAC over the client public key (could be any data) using `mac_key`
    char mac[MAC_SIZE];
    hmac(der, size, mac);

    printf("HMAC over certificate: %.*s\n", MAC_SIZE, mac);

    clean_up();

    return 0;
}
