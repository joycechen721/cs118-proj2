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

// helper functions
void send_ACK(uint32_t left_window_index, int sockfd, struct sockaddr_in clientaddr);
void *create_server_hello(int comm_type, uint8_t *client_nonce);

// global variables
#define BUF_SIZE 1024
#define CONGESTION_WINDOW_SIZE 20 // at any point there should be max 20 unacked packets
#define MAX_SEGMENT_SIZE 10 // payload size for each packet (bytes)
#define MAX_PACKET_SEND_SIZE 2001
#define RTO 1 // retransmission timer

int main(int argc, char *argv[]) {
    // Parse the arguments
    int flag = atoi(argv[1]);
    int port = atoi(argv[2]);

    /* 1. Create socket */
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    // Setup fd set for nonblock
    int flags = fcntl(sockfd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(sockfd, F_SETFL, flags);
    fcntl(STDIN_FILENO, F_SETFL, flags);

    /* 2. Construct & bind to our address */
    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET; // use IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(port); // Big endian
    int did_bind = bind(sockfd, (struct sockaddr*) &servaddr, sizeof(servaddr));
    if (did_bind < 0) return errno;

    // Same information, but about client
    struct sockaddr_in clientaddr;
    socklen_t clientsize = sizeof(clientaddr);

    // security stuff
    if (flag == 1) {
        char *private_key_file = argv[3];
        char *certificate_file = argv[4];

        // load private key & certificate
        load_private_key(private_key_file);
        load_certificate(certificate_file);

        // security handshake
        void *packets[2] = {nullptr};
        int handshake_left_ptr = 0;

        // initialize timer
        bool handshake_timer_active = false;
        struct timeval handshake_timer_start;

        while (handshake_left_ptr < 2)
        {
            // receive client hello
            char client_hello_buf[BUF_SIZE];
            int bytes_recvd = recvfrom(sockfd, client_hello_buf, BUF_SIZE, 0, (struct sockaddr *)&clientaddr, &clientsize);
            ClientHello *client_hello = (ClientHello *) client_hello_buf;
            uint8_t client_comm_type = client_hello->comm_type;
            uint8_t client_nonce[32] = {0};
            memcpy(client_nonce, client_hello->client_nonce, 32);

            // send server hello
            create_server_hello(client_comm_type, client_nonce);

            // start timer
            struct timeval now;
            gettimeofday(&now, NULL);
            double elapsed_time = (now.tv_sec - handshake_timer_start.tv_sec) + (now.tv_usec - handshake_timer_start.tv_usec) / 1e6;
            if (elapsed_time >= RTO) break;
                    
            // receive key exchange message
            char exchange_buf[BUF_SIZE];
            int bytes_recvd = recvfrom(sockfd, exchange_buf, BUF_SIZE, 0, (struct sockaddr *)&clientaddr, &clientsize);

            if (bytes_recvd > 0)
            {
                if (handshake_left_ptr == 0)
                {
                    // extract data from key exchange msg
                    KeyExchangeRequest client_key = (KeyExchangeRequest *) exchange_buf;
                    uint16_t cert_size = ntohs(client_key->cert_size);
                    Certificate client_cert = client_key->client_cert;

                    // verify client certificate
                    if (!verify((char*) client_cert, sizeof(Certificate), (char*)client_cert->signature, sizeof(client_cert->signature), public_key)) {
                        fprintf(stderr, "Verification of client certificate or signature failed.\n");
                        close(sockfd);
                        exit(EXIT_FAILURE);
                    }
                    
                    // verify client nonce
                    if (!verify((char*) client_nonce, client_nonce_size, (char*) signed_nonce, signed_nonce_size, ec_peer_public_key)) {
                        fprintf(stderr, "Verification of client certificate or signature failed.\n");
                        close(sockfd);
                        exit(EXIT_FAILURE);
                    }

                    // extract client public key from certificate
                    load_peer_public_key(client_cert, cert_size);

                    // derive shared secret
                    derive_secret();
                }
            }
        }
    }

    // buffer for packets received from server
    Packet* server_window[MAX_PACKET_SEND_SIZE] = {NULL};
    int curr_packet_num = 1;
    int left_pointer = 1; 
    int right_pointer = 20;

    // buffer for packets to send out
    Packet* input_window[MAX_PACKET_SEND_SIZE] = {NULL};
    int input_left = 1; // oldest unacked packet (leftmost)
    int input_right = 19;

    // initialize timer
    bool timer_active = false;
    struct timeval timer_start;
    bool client_send = false;
    while (true) {
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
                    int did_send = sendto(sockfd, retransmit, sizeof(Packet) + ntohs(retransmit->payload_size), 0, (struct sockaddr *)&clientaddr, clientsize);
                    if (did_send < 0) {
                        perror("Retransmit failed");
                    }
                }
                // reset timer
                gettimeofday(&timer_start, NULL);
            }
        }

        // receive data from client
        char client_buf[BUF_SIZE];
        socklen_t clientsize = sizeof(clientaddr);
        int bytes_recvd = recvfrom(sockfd, client_buf, BUF_SIZE, 0, (struct sockaddr*) &clientaddr, &clientsize);
        if (bytes_recvd > 0) {
            client_send = true;
            Packet* received_packet = (Packet*)client_buf;
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
                while (server_window[left_pointer] != NULL) {
                    uint8_t *payload = received_packet->data;
                    write(1, payload, received_payload_size);
                    left_pointer += 1;
                    if (left_pointer < MAX_PACKET_SEND_SIZE - 20) {
                        right_pointer += 1;
                    }
                }
                // Now we can send the cumulative ack
                send_ACK(left_pointer, sockfd, clientaddr);
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

        // read from stdin & send data to server
        char read_buf[BUF_SIZE];
        memset(read_buf, 0, BUF_SIZE);
        ssize_t bytesRead = read(STDIN_FILENO, read_buf, MAX_SEGMENT_SIZE);
        if (client_send && bytesRead > 0 && curr_packet_num >= input_left && curr_packet_num <= input_right) {
            // create a new packet
            Packet* new_packet = (Packet*)malloc(sizeof(Packet) + bytesRead);
            new_packet->packet_number = htonl(curr_packet_num);
            new_packet->acknowledgment_number = 0;
            new_packet->payload_size = htons(bytesRead);
            memcpy(new_packet->data, read_buf, bytesRead);

            input_window[curr_packet_num] = new_packet;
            curr_packet_num += 1;

            // send the packet
            int did_send = sendto(sockfd, new_packet, sizeof(Packet) + bytesRead, 0, (struct sockaddr *)&clientaddr, sizeof(clientaddr));
            if (did_send < 0){ 
                perror("error sending");
                return errno;
            }

            // reset timer
            if (!timer_active) {
                timer_active = true;
                gettimeofday(&timer_start, NULL);
            }
        }
    }
    /* 8. You're done! Terminate the connection */     
    close(sockfd);
    return 0;
}

// send ServerHello message back to client
void *create_server_hello(int comm_type, uint8_t *client_nonce){
    ServerHello* server_hello = (ServerHello*)malloc(sizeof(ServerHello));
    if (server_hello == nullptr) {
        fprintf(stderr, "Memory allocation failed for ServerHello.\n");
        return nullptr;
    }
    // extract comm type
    server_hello->comm_type = comm_type;
    
    // generate server nonce
    char server_nonce_buf[32];
    generate_nonce(server_nonce_buf, 32);
    memcpy(server_hello->server_nonce, server_nonce_buf, 32);
   
    // certificate
    server_hello->server_cert = certificate;

    // sign client nonce
    size_t sig_size = sign(client_nonce, sizeof(&client_nonce), NULL);
    char signature[sig_size];
    sign(client_nonce, sizeof(&client_nonce), signature)
    memcpy(server_hello->client_nonce, signature, sig_size);
    server_hello->sig_size = sig_size;

    return server_hello;
}

// Sends cumulative ACK depending on the packet number received
void send_ACK(uint32_t left_window_index, int sockfd, struct sockaddr_in clientaddr) {
    Packet ack_packet = {0};
    ack_packet.acknowledgment_number = htonl(left_window_index);
    sendto(sockfd, &ack_packet, sizeof(ack_packet), 0, (struct sockaddr *)&clientaddr, sizeof(clientaddr));
}