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
    uint8_t padding[2];
    uint16_t msg_len;
} SecurityHeader;

typedef struct {
    SecurityHeader header;
    uint16_t key_len;
    uint16_t padding[4];
    uint32_t public_key;
    uint32_t signature;
} Certificate;

typedef struct {
    SecurityHeader header;
    uint8_t comm_type;
    uint16_t padding[4];
    uint32_t client_nonce;
} ClientHello;

typedef struct {
    SecurityHeader header;
    uint8_t comm_type;
    uint8_t sig_size;
    uint16_t cert_size;
    uint32_t server_nonce;
    uint32_t server_cert;
    uint32_t client_sig;
} ServerHello;

typedef struct {
    SecurityHeader header;
    uint8_t padding;
    uint8_t sig_size;
    uint16_t cert_size;
    uint32_t client_cert;
    uint32_t server_sig;
} KeyExchangeRequest;

typedef struct {
    SecurityHeader header;
    uint16_t payload_size;
    uint16_t padding;
    uint32_t init_vector;
    uint32_t payload;
    uint32_t mac_code;
} EncryptedData;

typedef struct {
    SecurityHeader header;  // Common security header
} Finished;

#endif // PACKET_H
