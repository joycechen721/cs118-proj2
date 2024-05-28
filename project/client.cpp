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
void *create_key_exchange(uint8_t *client_nonce, uint8_t *server_nonce, uint8_t *signed_nonce, size_t client_nonce_size, size_t signed_nonce_size, Certificate *server_cert, EVP_PKEY *ca_public_key, int sockfd, struct sockaddr_in serveraddr);

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
                uint8_t server_sig_size = server_hello->sig_size;
                uint16_t server_cert_size = server_hello->cert_size;
                uint8_t server_nonce[32] = {0};
                memcpy(server_nonce, server_hello->server_nonce, 32);

                // Check if the server certificate size is valid
                if (server_cert_size == 0) {
                    fprintf(stderr, "Invalid server certificate size: %u\n", server_cert_size);
                    close(sockfd);
                    exit(EXIT_FAILURE);
                }

                // Allocate memory for the server certificate
                Certificate* server_cert = (Certificate*)malloc(server_cert_size);

                // Correct way to copy the certificate data
                memcpy(server_cert, &server_hello->server_cert, server_cert_size);
                if (server_cert -> public_key == NULL) {
                    fprintf(stderr, "Memory allocation failed for server certificate.\n");
                    close(sockfd);
                    exit(EXIT_FAILURE);
                }
                // Print the server certificate size for debugging
                uint8_t* client_nonce_signed = (uint8_t*)malloc(server_sig_size);
                if (client_nonce_signed == NULL) {
                    fprintf(stderr, "Memory allocation failed for client nonce signed.\n");
                    close(sockfd);
                    exit(EXIT_FAILURE);
                }
                memcpy(client_nonce_signed, server_hello->client_nonce, server_sig_size);

                if (packets[1] == NULL) //if packets[1] is null then create key exchange and increment left so you can retransmit properly
                {
                    packets[1] = create_key_exchange(client_nonce_buf, server_nonce, client_nonce_signed, 32, server_sig_size, server_cert, ec_ca_public_key, sockfd, serveraddr);
                    handshake_left_ptr += 1; 
                    sendto(sockfd, packets[handshake_left_ptr], sizeof(KeyExchangeRequest), 0, (struct sockaddr *)&serveraddr, serversize);
                }
            }

            else if(handshake_left_ptr ==1 && bytes_recvd == sizeof(SecurityHeader)){
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

void *create_key_exchange(uint8_t* client_nonce, uint8_t *server_nonce, uint8_t *signed_nonce, size_t client_nonce_size, size_t signed_nonce_size, Certificate* server_cert, EVP_PKEY* ca_public_key, int sockfd, struct sockaddr_in serveraddr) {
    ec_ca_public_key = ca_public_key; 

    printf("server public key: %s, size: %ld", (char*) server_cert->public_key, sizeof(server_cert->public_key));

    load_peer_public_key((char*)server_cert->public_key, server_cert->key_len);
    if(ec_peer_public_key == NULL){
        printf("errrrr\n");
    }
    // Verify server certificate and signature
    if (!verify((char*) server_cert, sizeof(Certificate), (char*)server_cert -> signature, sizeof(server_cert -> signature), ca_public_key)) {
        fprintf(stderr, "Verification of server certificate failed.\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    if (!verify((char*) client_nonce, client_nonce_size, (char*)signed_nonce, signed_nonce_size, ec_peer_public_key)) {
        fprintf(stderr, "Verification of signature failed.\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    derive_secret();  //now secret variable has the private key
    generate_private_key(); //now private key is stored in private key var 
    derive_public_key(); //now public key is stored in variable "public_key"
    //now we have to sign the server nonce now
    unsigned char* signature = NULL;
    size_t signature_size = sign((char*)server_nonce, sizeof(*server_nonce), (char*)signature);
    if (signature == NULL) {
            fprintf(stderr, "Failed to sign the server nonce.\n");
            close(sockfd);
            exit(EXIT_FAILURE);
    }
    //now we need to create a certificate and sign the certificate with our own private key
    Certificate* client_cert = NULL;

    // Calculate the size needed for the signature
    size_t temp_signature_size = sign((char*)client_cert, sizeof(client_cert->key_len) + sizeof(client_cert->padding) + sizeof(client_cert->public_key), NULL);

    // Allocate memory for client_cert
    client_cert = (Certificate*)malloc(sizeof(Certificate) + pub_key_size + temp_signature_size);
    if (client_cert == NULL) {
        fprintf(stderr, "Failed to allocate memory for client certificate.\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    // Initialize client_cert
    memset(client_cert, 0, sizeof(Certificate) + sizeof(client_cert->key_len)  + temp_signature_size); //zero out entire cert initially
    client_cert -> key_len = pub_key_size; 
    memcpy(client_cert->public_key, public_key, pub_key_size); 

    // Sign the certificate
    unsigned char* certificate_signature = NULL;
    sign((char*)client_cert, sizeof(client_cert -> key_len) + sizeof(client_cert -> padding) + sizeof(client_cert -> public_key), (char*) certificate_signature);
    memcpy(client_cert -> signature, certificate_signature, temp_signature_size);
    //now create the keyexchage packet
    KeyExchangeRequest* key_exchange = (KeyExchangeRequest*) malloc(sizeof(KeyExchangeRequest) + pub_key_size + temp_signature_size + signature_size); //may be wrong on this
    memset(key_exchange, 0, sizeof(KeyExchangeRequest) + pub_key_size + temp_signature_size + signature_size); 
    key_exchange -> sig_size = signature_size; 
    key_exchange -> cert_size = temp_signature_size; 
    key_exchange -> client_cert = *client_cert; 
    memcpy(key_exchange->server_sig, signature, temp_signature_size); 


    key_exchange -> header.msg_type = KEY_EXCHANGE_REQUEST; 
    key_exchange -> header.padding = 0; 
    key_exchange -> header.msg_len = sizeof(key_exchange) - sizeof(SecurityHeader); 
    
    return key_exchange; 
}
