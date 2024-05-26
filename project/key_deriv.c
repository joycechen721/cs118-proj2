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

    printf("Server side secret: %.*s\n", 32, secret);

    /* Client side */

    // Load client private key from file
    load_private_key("../keys/client_priv_key.bin");

    // Load server public key (typically over the network)
    fp = fopen("../keys/pub_key.bin", "r");
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, 0);
    fread(der, size, 1, fp);
    load_peer_public_key(der, size);

    // Derive ECDH secret
    derive_secret();

    printf("Client side secret: %.*s\n", 32, secret);

    clean_up();

    return 0;
}