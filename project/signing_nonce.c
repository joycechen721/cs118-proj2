#include <unistd.h>
#include <stdio.h>

#include "security.h"

int main() {
    // Load private key from file and derive public key
    load_private_key("../keys/priv_key.bin");
    derive_public_key();
    load_peer_public_key(public_key, pub_key_size);

    // Generate nonce
    char nonce[32];
    generate_nonce(nonce, 32);

    printf("Nonce: %.*s\n", 32, nonce);

    // Sign nonce with private key
    char sig[255];
    size_t sig_size = sign(nonce, 32, sig);

    printf("Signature: %.*s\n", (int) sig_size, sig);

    // Verify nonce with public key
    int verified = verify(nonce, 32, sig, sig_size, ec_peer_public_key);

    printf(verified == 1 ? "Verified nonce successfully\n" : "Could not verify nonce");

    clean_up();

    return 0;
}