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

typedef enum {
    CLIENT_HELLO = 1,
    SERVER_HELLO = 2,
    KEY_EXCHANGE_REQUEST = 16,
    FINISHED = 20,
    DATA = 255
} MsgType;

typedef struct {
    MsgType msg_type;
    uint8_t padding;
    uint16_t msg_len;
} SecurityHeader;

typedef struct {
    SecurityHeader header;
    uint16_t key_len;
    uint16_t padding;
    uint8_t public_key[0];
    uint8_t signature[0];
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
    Certificate server_cert;
    uint8_t client_nonce[0];
} ServerHello;

typedef struct {
    SecurityHeader header;
    uint8_t padding;
    uint8_t sig_size;
    uint16_t cert_size;
    Certificate client_cert;
    uint8_t server_sig[0];
} KeyExchangeRequest;

typedef struct {
    SecurityHeader header;
    uint16_t payload_size;
    uint16_t padding;
    uint8_t init_vector[16];
    uint8_t payload[0];
    uint8_t mac_code[32];
} EncryptedData;

typedef struct {
    SecurityHeader header;  // Common security header
} Finished;

#endif // PACKET_H
