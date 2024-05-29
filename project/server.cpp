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
Packet *create_server_hello(int comm_type, uint8_t *client_nonce);
Packet *create_fin();

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
    bool handshake = false;
    if(flag){
        handshake = true;
    }
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
        if(handshake){ //if handshake still ongoing
            if(server_window[1] != NULL && input_window[1] == NULL){//can only make server hello if we recieve client hellow and input window 0 is null
                Packet* client_hello_packet = server_window[1];
                ClientHello *client_hello = (ClientHello *) client_hello_packet -> data;
                uint8_t client_comm_type = client_hello->comm_type;
                uint8_t client_nonce[32] = {0};
                memcpy(client_nonce, client_hello->client_nonce, 32);
                // send server hello
                Packet* server_hello = create_server_hello(client_comm_type, client_nonce);
                input_window[1] = server_hello;
                ServerHello* srvh = (ServerHello*) input_window[1] -> data; 
                printf("server hello size %ld\n", sizeof(Packet) + server_hello -> payload_size);
                // Send ACK
                sendto(sockfd, server_hello, sizeof(Packet) + server_hello -> payload_size, 0, (struct sockaddr *)&clientaddr, sizeof(clientaddr));
            }
            else if(server_window[2] != NULL && input_window[2] == NULL){ //this means we have recieved key exchange, need to parse it
                Packet* key_exchange_packet = server_window[2];
                KeyExchangeRequest* key_exchange = (KeyExchangeRequest*) key_exchange_packet -> data; 
                uint16_t client_cert_size = key_exchange->cert_size;
                // Extract certificate from key_exchange-> data
                uint8_t raw_cert_buf[client_cert_size];
                memcpy(raw_cert_buf, key_exchange->data, client_cert_size);
                Certificate* client_cert = (Certificate *) raw_cert_buf;
                    
                uint8_t sig_size = key_exchange->sig_size;
                uint8_t server_sig[32] = {0};
                memcpy(server_sig, key_exchange->data + sig_size, 32);

                uint16_t key_len = client_cert->key_len;
                // int key_len = ntohs(client_cert->key_len);
                uint8_t *client_public_key = client_cert->data;
                load_peer_public_key((char*) client_cert->data, client_cert->key_len);
                FILE *file = fopen("public_key.txt", "w");
                if (file == NULL) {
                    fprintf(stderr, "Error opening file.\n");
                    return 1; // Or handle the error appropriately
                }

                // Write the data into the file
                for (size_t i = 0; i < client_cert->key_len; i++) {
                    fprintf(file, "%02hhX ", (unsigned char)client_cert->data[i]);
                }
                fclose(file);

                uint8_t *signature = client_cert->data + key_len-1;
                size_t signature_len = client_cert_size - (sizeof(uint16_t) + sizeof(uint16_t) + key_len);
                // verify client certificate
                // int verify(char* data, size_t size, char* signature, size_t sig_size, EVP_PKEY* authority)
                if (!verify((char*) client_public_key, key_len, (char*) signature, signature_len, ec_peer_public_key)) {
                    fprintf(stderr, "Verification of client certificate failed.\n");
                    close(sockfd);
                    exit(EXIT_FAILURE);
                } 


                
                // verify client nonce
                if (!verify((char*) server_sig, sizeof(*server_sig), (char*) server_sig, sig_size, ec_peer_public_key)) {
                    fprintf(stderr, "Verification of client signature failed.\n");
                    close(sockfd);
                    exit(EXIT_FAILURE);
                }

                // derive shared secret
                derive_secret();

                Packet* server_fin = create_fin();
                input_window[2] = server_fin;
                int did_send = sendto(sockfd, server_fin, sizeof(Packet) + server_fin -> payload_size , 0, (struct sockaddr *)&clientaddr, clientsize);
                if (did_send < 0) {
                    perror("Failed to send server fin msg");
                }
            }
        }
        // receive data from client
        char client_buf[BUF_SIZE];
        socklen_t clientsize = sizeof(clientaddr);
        int bytes_recvd = recvfrom(sockfd, client_buf, BUF_SIZE, 0, (struct sockaddr*) &clientaddr, &clientsize);
        if (bytes_recvd > 0) {
            client_send = true;
            Packet* received_packet = (Packet*)client_buf;
            uint32_t received_packet_number = (received_packet->packet_number);
            uint32_t received_ack_number = ntohl(received_packet->acknowledgment_number);
            uint16_t received_payload_size = (received_packet->payload_size);
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
                if(!handshake){
                    while (server_window[left_pointer] != NULL) {
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
                    send_ACK(left_pointer, sockfd, clientaddr);
                }
                else{
                    printf("revd pack num%d\n",received_packet_number );
                    send_ACK(received_packet_number + 1, sockfd, clientaddr);
                }
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
                else if(handshake){
                    curr_packet_num = received_ack_number;
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

// send fin message to client
Packet *create_fin() {
    Finished* server_fin = (Finished*)malloc(sizeof(Finished));
    server_fin -> header.msg_type = FINISHED; 
    server_fin -> header.padding = 0; 
    server_fin -> header.msg_len = sizeof(server_fin) - sizeof(SecurityHeader); 
    Packet* packet = (Packet*)malloc(sizeof(Packet) + sizeof(Finished));
    if (!packet) {
        perror("Failed to allocate memory for packet");
        free(server_fin);
        exit(EXIT_FAILURE);
    }

    // Fill in the packet fields
    packet->packet_number = 2; 
    packet -> acknowledgment_number = 0;
    packet->payload_size = sizeof(Finished);
    memcpy(packet->data, server_fin, sizeof(Finished));

    // Free the temporary Finished message memory
    free(server_fin);
    return packet;
}

// send ServerHello message back to client
Packet *create_server_hello(int comm_type, uint8_t *client_nonce){
    size_t sig_size = sign((char*)client_nonce, sizeof(*client_nonce), NULL);

    ServerHello* server_hello = (ServerHello*)malloc(sizeof(ServerHello) + sizeof(Certificate) + cert_size + sig_size);

    if (server_hello == nullptr) {
        fprintf(stderr, "Memory allocation failed for ServerHello.\n");
        return nullptr;
    }
    server_hello -> header.msg_type = SERVER_HELLO; 
    server_hello -> header.padding = 0; 

    // set comm type
    server_hello->comm_type = comm_type;
    
    // generate server nonce
    char server_nonce_buf[32];
    generate_nonce(server_nonce_buf, 32);
    memcpy(server_hello->server_nonce, server_nonce_buf, 32);
   
    // certificate
    memcpy(server_hello->data, certificate, cert_size);
    server_hello->cert_size = cert_size;

    char *server_nonce_sig = (char*)malloc(sig_size);
    sign((char*)client_nonce, sizeof(*client_nonce), server_nonce_sig);
    memcpy(server_hello->data + cert_size, server_nonce_sig, sig_size);
    printf("data size %ld\n", cert_size + sig_size);   

    server_hello->sig_size = sig_size;
    free(server_nonce_sig);
    server_hello -> header.msg_len = sizeof(server_hello) - sizeof(SecurityHeader);

    size_t server_hello_size = sizeof(ServerHello) + cert_size + sig_size;
    Packet* packet = (Packet*)malloc(sizeof(Packet) + server_hello_size);
    if (!packet) {
        perror("Failed to allocate memory for packet");
        free(server_hello);
        exit(EXIT_FAILURE);
    }
    packet->packet_number = 1;
    packet -> acknowledgment_number = 0;
    memset(packet->padding, 0, sizeof(packet->padding));
    packet->payload_size = server_hello_size;
    memcpy(packet->data, server_hello, server_hello_size);
    free(server_hello);
    return packet;
}

// Sends cumulative ACK depending on the packet number received
void send_ACK(uint32_t left_window_index, int sockfd, struct sockaddr_in clientaddr) {
    Packet ack_packet = {0};
    ack_packet.acknowledgment_number = htonl(left_window_index);
    sendto(sockfd, &ack_packet, sizeof(ack_packet), 0, (struct sockaddr *)&clientaddr, sizeof(clientaddr));
}