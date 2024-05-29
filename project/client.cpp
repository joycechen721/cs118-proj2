#include <iostream>
#include <sys/socket.h> // Socket interface
#include <sys/time.h>
#include <arpa/inet.h>  // Internet protocol
#include <string.h>     // strlen
#include <unistd.h>     // close, etc.
#include <errno.h>      // Get errorno
#include <stdio.h>
#include <fcntl.h>
#include "packet_format.h"
#include "security.h"

// Global variables
#define BUF_SIZE 1024
#define CONGESTION_WINDOW_SIZE 20 // at any point there should be max 20 unacked packets
#define MAX_SEGMENT_SIZE 10       // payload size for each packet (bytes)
#define MAX_PACKET_SEND_SIZE 2001
#define RTO 1 // retransmission timer

// Function prototypes
void send_ACK(uint32_t left_window_index, int sockfd, struct sockaddr_in serveraddr);
void *create_client_hello(uint8_t *client_nonce);
KeyExchangeRequest *create_key_exchange(char *client_nonce, char *server_nonce, char *signed_nonce, size_t signed_nonce_size, Certificate *server_cert, int sockfd, struct sockaddr_in serveraddr);

int main(int argc, char *argv[])
{
    // Parse the arguments
    if (argc < 5)
    {
        std::cerr << "Usage: " << argv[0] << " <flag> <hostname> <port> <ca_public_key_file>\n";
        return 1;
    }

    int flag = atoi(argv[1]);
    char *hostname = argv[2];
    int port = atoi(argv[3]);
    char *ca_public_key_file = argv[4];

    // Load CA public key
    load_ca_public_key(ca_public_key_file);

    // Create socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("socket creation failed");
        return 1;
    }

    // Setup fd/stdin set for nonblock
    int flags = fcntl(sockfd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(sockfd, F_SETFL, flags);
    fcntl(STDIN_FILENO, F_SETFL, flags);

    // Construct server address
    struct sockaddr_in serveraddr;
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = INADDR_ANY;
    serveraddr.sin_port = htons(port);
    socklen_t serversize = sizeof(serveraddr);

    //while loop for handling security stuff
    void *packets[2] = {nullptr};
    int handshake_left_ptr = 0;
    packets[0] = create_client_hello(nullptr);
    sendto(sockfd, packets[0], sizeof(ClientHello), 0, (struct sockaddr *)&serveraddr, serversize);
    uint8_t client_nonce_buf[32] = {0};
    memcpy(client_nonce_buf,((ClientHello*)packets[0])->client_nonce, 32);
    struct timeval handshake_timer_start;
    gettimeofday(&handshake_timer_start, NULL);
    struct timeval now;
    gettimeofday(&now, NULL);
    while (handshake_left_ptr < 2)
    {
        double elapsed_time = (now.tv_sec - handshake_timer_start.tv_sec) + (now.tv_usec - handshake_timer_start.tv_usec) / 1e6;
        if (elapsed_time >= RTO)
        {
            if(handshake_left_ptr == 0){
                sendto(sockfd, packets[handshake_left_ptr], sizeof(ClientHello), 0, (struct sockaddr *)&serveraddr, serversize);
            }
            else{
                sendto(sockfd, packets[handshake_left_ptr], sizeof(KeyExchangeRequest), 0, (struct sockaddr *)&serveraddr, serversize);
            }
            gettimeofday(&handshake_timer_start, NULL);
        }
        char handshake_buf[BUF_SIZE];
        int bytes_recvd = recvfrom(sockfd, handshake_buf, BUF_SIZE, 0, (struct sockaddr *)&serveraddr, &serversize);
        if (bytes_recvd > 0)
        {
            if (handshake_left_ptr == 0){ //received the server hello
                gettimeofday(&handshake_timer_start, NULL); //reset timer
                ServerHello *server_hello = (ServerHello *)handshake_buf;

                uint8_t server_comm_type = server_hello->comm_type;
                uint8_t server_sig_size = (server_hello->sig_size);

                // extract server certificate
                uint16_t server_cert_size = server_hello->cert_size;
                // Check if the server certificate size is valid
                if (server_cert_size == 0) {
                    fprintf(stderr, "Invalid server certificate size: %u\n", server_cert_size);
                    close(sockfd);
                    exit(EXIT_FAILURE);
                }
                uint8_t raw_cert_buf[server_cert_size];
                memcpy(raw_cert_buf, server_hello->data, server_cert_size);
                // ERRROR HERE ASK OMAR
                Certificate* server_cert = (Certificate*) raw_cert_buf;

                int key_len = ntohs(server_cert->key_len);
                printf("certificate key length %d\n", key_len);
                printf("certificate length %u\n", server_cert_size);
                printf("signature length %d\n", server_sig_size);

                uint8_t server_nonce[32] = {0};
                memcpy(server_nonce, server_hello->server_nonce, 32);
                printf("server nonce length %ld\n", sizeof(server_nonce));

                // extract server signature
                uint8_t client_nonce_signed[server_sig_size];
                memcpy(client_nonce_signed, server_hello->data + (int) server_cert_size, server_sig_size);
                                
                uint8_t* pub_key = (uint8_t*)malloc(key_len);
                if (pub_key == NULL) {
                    fprintf(stderr, "Memory allocation failed for client nonce signed.\n");
                    close(sockfd);
                    exit(EXIT_FAILURE);
                }
                memcpy(pub_key, server_cert->data, key_len);

                if (packets[1] == NULL) //if packets[1] is null then create key exchange and increment left so you can retransmit properly
                {                    
                    // void *create_key_exchange(uint8_t *client_nonce, uint8_t *server_nonce, uint8_t *signed_nonce, size_t signed_nonce_size, Certificate *server_cert, EVP_PKEY *ca_public_key, int sockfd, struct sockaddr_in serveraddr);

                    KeyExchangeRequest* key_xchange = create_key_exchange(
                        (char*) client_nonce_buf, 
                        (char*) server_nonce, 
                        (char*) client_nonce_signed, 
                        server_sig_size,
                        server_cert, 
                        sockfd, 
                        serveraddr
                    );

                    handshake_left_ptr += 1; 
                    sendto(sockfd, key_xchange, sizeof(KeyExchangeRequest) + sizeof(Certificate) + key_xchange->cert_size + key_xchange->sig_size, 0, (struct sockaddr *)&serveraddr, serversize);
                }
            }

            else if(handshake_left_ptr ==1 && bytes_recvd == sizeof(SecurityHeader)){
                // Print the contents of secret
                    if (secret != NULL) {
                        for (size_t i = 0; i < sizeof(secret); ++i) {
                            printf("%02x ", (unsigned char)secret[i]);
                        }
                        printf("\n");


                        printf("secret: %s\n", secret);
                    } else {
                        printf("secret is NULL\n");
                    }
                handshake_left_ptr +=1; 
            }
        }
    }

    // buffer for packets received from client
    Packet *server_window[MAX_PACKET_SEND_SIZE] = {nullptr};
    int curr_packet_num = 1;
    int left_pointer = 1;
    int right_pointer = 20;

    // buffer for packets to send out
    Packet *input_window[MAX_PACKET_SEND_SIZE] = {nullptr};
    int input_left = 1; // oldest unacked packet (leftmost)
    int input_right = 19;
    // initialize timer
    bool timer_active = false;
   

    struct timeval timer_start;
    while(true){
        // retransmission from rto
        if (timer_active) {
            struct timeval now;
            gettimeofday(&now, NULL);
            double elapsed_time = (now.tv_sec - timer_start.tv_sec) + (now.tv_usec - timer_start.tv_usec) / 1e6;
            // timer expired
            if (elapsed_time >= RTO) {
                // retransmit leftmost unacked packet if not NULL
                Packet* retransmit = input_window[input_left];
                if (retransmit) {
                    printf("Retransmitting packet with size: %ld\n", sizeof(Packet) + ntohs(retransmit->payload_size));
                    int did_send = sendto(sockfd, retransmit, sizeof(Packet) + ntohs(retransmit->payload_size), 0, (struct sockaddr *)&serveraddr, serversize);
                    if (did_send < 0) {
                        perror("Retransmit failed");
                    }
                }
                // reset timer
                gettimeofday(&timer_start, NULL);
            }
        }

        // read from stdin & send data to server
        char read_buf[BUF_SIZE];
        // memset(read_buf, 0, BUF_SIZE);
        ssize_t bytesRead = read(STDIN_FILENO, read_buf, MAX_SEGMENT_SIZE);
        if (bytesRead > 0 && curr_packet_num >= input_left && curr_packet_num <= input_right) {
            // create a new packet
            Packet* new_packet = (Packet*)malloc(sizeof(Packet) + bytesRead);
            new_packet->packet_number = htonl(curr_packet_num);
            new_packet->acknowledgment_number = 0;
            new_packet->payload_size = htons(bytesRead);
            memcpy(new_packet->data, read_buf, bytesRead);

            input_window[curr_packet_num] = new_packet;
            curr_packet_num += 1;

            // send the packet
            int did_send = sendto(sockfd, new_packet, sizeof(Packet) + bytesRead, 0, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
            if (did_send < 0) return errno;

            // reset timer
            if (!timer_active) {
                timer_active = true;
                gettimeofday(&timer_start, NULL);
            }
        }

        // receive data from server
        char server_buf[BUF_SIZE];
        // socklen_t serversize = sizeof(serveraddr);
        int bytes_recvd = recvfrom(sockfd, server_buf, BUF_SIZE, 0, (struct sockaddr*)&serveraddr, &serversize);
        if (bytes_recvd > 0) {
            Packet* received_packet = (Packet*)server_buf;
            uint32_t received_packet_number = ntohl(received_packet->packet_number);
            uint32_t received_ack_number = ntohl(received_packet->acknowledgment_number);
            uint16_t received_payload_size = ntohs(received_packet->payload_size);
            // receive data --> send an ack
            if (received_packet_number != 0) {
                // Update window to reflect new packet
                server_window[received_packet_number] = (Packet*)malloc(sizeof(Packet) + received_payload_size);
                if (server_window[received_packet_number] == NULL) {
                    perror("Memory allocation failed");
                    close(sockfd);
                    return 1;
                }
                memcpy(server_window[received_packet_number], received_packet, sizeof(Packet) + received_payload_size);

                // Update left pointer until it points to nothing, adjust right pointer too
                while (server_window[left_pointer] != NULL) { //move sender window forward since received acked
                    uint8_t *payload = received_packet->data;
                    write(1, payload, received_payload_size);
                    if (server_window[left_pointer] != NULL) {
                        free(server_window[left_pointer]);
                        server_window[left_pointer] = NULL;
                    }
                    left_pointer += 1;
                    if (left_pointer < MAX_PACKET_SEND_SIZE - 20) {
                        right_pointer += 1;
                    }
                }
                // Now we can send the cumulative ack
                send_ACK(left_pointer, sockfd, serveraddr);
            } 
            // receive an ack --> update input window
            else {
                printf("received ack: %d\n", received_ack_number);
                if (received_ack_number > input_left) {
                    // free packets from input_left to ack #
                    for (int i = input_left; i < received_ack_number; i++) {
                        if (input_window[i] != NULL) {
                            free(input_window[i]);
                            input_window[i] = NULL;
                        }
                    }
                    input_left = received_ack_number;
                    input_right = 20 + input_left;

                    // cancel timer if no unacked packets
                    if (input_left == curr_packet_num) {
                        timer_active = false;
                    } 
                    // reset timer otherwise
                    else {
                        gettimeofday(&timer_start, NULL);
                    }
                }
            }
        }
        // TEST CODE for SEND:
        // // char received_buf[] = "Hello earth!";
        // int did_send = sendto(sockfd, received_buf, strlen(received_buf), 0, (struct sockaddr*) &serveraddr, sizeof(serveraddr));
        // if (did_send < 0) continue;

        /* 4. Create buffer to store incoming data */
        // write(1, server_buf, bytes_recvd);
    }
    /* 6. You're done! Terminate the connection */     
    close(sockfd);
    return 0;
}

// Sends cumulative ACK depending on the packet number received
void send_ACK(uint32_t left_window_index, int sockfd, struct sockaddr_in serveraddr) {
    Packet ack_packet = {0};
    ack_packet.acknowledgment_number = htonl(left_window_index);
    sendto(sockfd, &ack_packet, sizeof(ack_packet), 0, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
}

void *create_client_hello(uint8_t *client_nonce){
    ClientHello* client_hello = (ClientHello*)malloc(sizeof(ClientHello));
    if (client_hello == nullptr) {
        fprintf(stderr, "Memory allocation failed for ClientHello.\n");
        return nullptr;
    }
    // Initialize comm_type based on flag
    client_hello->comm_type = 1; 
    // Initialize padding to zero
    client_hello->padding = 0; 
    // Generate client nonce
    char client_nonce_buf[32]; // 32 bytes for the nonce
    generate_nonce(client_nonce_buf, 32); // fill nonce_buf with 32 bytes of data
    memcpy(client_hello->client_nonce, client_nonce_buf, 32);

    client_hello -> header.msg_type = CLIENT_HELLO; 
    client_hello -> header.padding = 0; 
    client_hello -> header.msg_len = sizeof(client_hello) - sizeof(SecurityHeader); 
    return client_hello;
}

KeyExchangeRequest *create_key_exchange(char* client_nonce, char *server_nonce, char *signed_nonce, size_t signed_nonce_size, Certificate* server_cert, int sockfd, struct sockaddr_in serveraddr) {
    load_peer_public_key((char*) server_cert->data, server_cert->key_len);
    if(ec_peer_public_key == NULL){
        printf("errrrrm what the sigma\n");
    }

    uint16_t key_len = server_cert -> key_len;
    uint8_t *server_public_key = server_cert -> data;
    size_t signature_len = cert_size - (2 * sizeof(uint16_t) + key_len);
    uint8_t *signature = server_public_key + key_len;

    // Verify server signature inside of the certificate
    if (!verify((char *) server_public_key, key_len, (char*) signature, signature_len, ec_ca_public_key)) {
        fprintf(stderr, "Verification of server certificate failed.\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("VERIFY SERVER CERT SUCCESS \n");
    
    if (!verify((char*) client_nonce, 32, (char*)signed_nonce, signed_nonce_size, ec_peer_public_key)) {
        fprintf(stderr, "Verification of signature failed.\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("VERIFY SERVER SIG SUCCESS \n");

    generate_private_key(); //now private key is stored in private key var 
    derive_public_key(); //now public key is stored in variable "public_key"
    derive_secret();  //now secret variable has the private key
    
    //now we need to create a certificate and sign the certificate with our own private key

    // Calculate the size needed for the public key signature
    size_t self_signature_size = sign((char*)public_key, sizeof(public_key), NULL);
    // Allocate memory for client certificate
    Certificate* client_cert = (Certificate*)malloc(sizeof(Certificate) + pub_key_size + self_signature_size);
    if (client_cert == NULL) {
        fprintf(stderr, "Failed to allocate memory for client certificate.\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    // Initialize client_cert
    client_cert -> key_len = pub_key_size; 
    printf("pub key size: %d\n", pub_key_size);
    client_cert -> padding = 0;
    memcpy(client_cert->data, public_key, pub_key_size); 

    size_t self_sig_size = sign((char*)public_key, sizeof(public_key), NULL);
    char *self_signature = (char*)malloc(self_sig_size);
    sign((char*)public_key, sizeof(public_key), self_signature);
    memcpy(client_cert->data + pub_key_size, self_signature, self_sig_size); 

    //now we have to sign the server nonce
    size_t nonce_signature_size = sign((char*)server_nonce, sizeof(server_nonce), NULL);
    char *nonce_signature = (char*)malloc(nonce_signature_size);
    sign((char*)client_nonce, sizeof(*client_nonce), nonce_signature);

    if (nonce_signature == NULL) {
        fprintf(stderr, "Failed to sign the server nonce.\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    //now create the keyexchage packet
    KeyExchangeRequest* key_exchange = (KeyExchangeRequest*) malloc(sizeof(KeyExchangeRequest) + sizeof(Certificate) + pub_key_size + self_signature_size + nonce_signature_size);
    // size of signature & certificate
    key_exchange -> sig_size = nonce_signature_size; 
    key_exchange -> cert_size = sizeof(Certificate) + self_signature_size + pub_key_size;
    printf("cert size: %ld\n", sizeof(Certificate) + self_signature_size + pub_key_size);
    // copy certificate into data
    memcpy(key_exchange->data, client_cert, sizeof(Certificate) + pub_key_size + self_signature_size); 
    printf("nonce signature size: %ld\n", nonce_signature_size);
    // copy signature of server nonce into data
    memcpy(key_exchange->data + key_exchange -> cert_size, nonce_signature, nonce_signature_size); 
    
    key_exchange -> header.msg_type = KEY_EXCHANGE_REQUEST; 
    key_exchange -> header.padding = 0; 
    key_exchange -> header.msg_len = sizeof(key_exchange) - sizeof(SecurityHeader); 
    
    return key_exchange; 
}
