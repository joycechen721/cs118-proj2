#ifndef PACKET_H
#define PACKET_H
#include <stdlib.h>

typedef struct {
    uint32_t packet_number;        // 32-bit Packet Number
    uint32_t acknowledgment_number; // 32-bit Acknowledgment Number
    uint16_t payload_size;         // 16-bit Payload Size
    uint8_t padding[2];              // 16-bit Padding
    uint8_t data[0];     
} Packet;

const uint8_t CLIENT_HELLO = 1;
const uint8_t SERVER_HELLO = 2;
const uint8_t KEY_EXCHANGE_REQUEST = 16;
const uint8_t FINISHED = 20;
const uint8_t DATA = 255;

// total 4 bytes
typedef struct {
    uint8_t msg_type; // Using uint8_t for one byte representation
    uint8_t padding;
    uint16_t msg_len;
} SecurityHeader;

typedef struct {
    uint16_t key_len;
    uint16_t padding;
    uint8_t data[0];
    // public key
    // uint8_t signature[0];
} Certificate;

typedef struct {
    SecurityHeader header;
    uint8_t comm_type;
    uint16_t padding;
    uint8_t client_nonce[32];
} ClientHello;

typedef struct {
    SecurityHeader header;
    uint8_t comm_type;
    uint8_t sig_size;
    uint16_t cert_size;
    uint8_t server_nonce[32];
    uint8_t data[0];
    // Certificate server_cert; //variable
    // signature of client nonce -- variable;
} ServerHello;

typedef struct {
    SecurityHeader header;
    uint8_t padding;
    uint8_t sig_size;
    uint16_t cert_size;
    uint8_t data[0];
    // Certificate client_cert; //variable
    // uint8_t server_sig[0];
} KeyExchangeRequest;

typedef struct {
    SecurityHeader header; // 4 bytes
    uint16_t payload_size; // 2 bytes
    uint16_t padding; // 2 bytes
    uint8_t init_vector[16]; // 16 bytes
    uint8_t data[0]; // payload + mac code (32 bytes)
    // uint8_t mac_code[32]; // 32 bytes
} EncryptedData;

typedef struct {
    SecurityHeader header;  // Common security header
} Finished;

#endif // PACKET_H
