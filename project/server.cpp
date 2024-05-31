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
Packet* read_from_stdin(int flag, bool encrypt_mac, Packet* input_window[], int &curr_packet_num, int input_left, int input_right, bool &timer_active, struct timeval &timer_start);

// global variables
#define BUF_SIZE 1024
#define CONGESTION_WINDOW_SIZE 20 // at any point there should be max 20 unacked packets
#define MAX_SEGMENT_SIZE 1024 // payload size for each packet (bytes)
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

    // security stuff
    bool handshake = false;
    bool encrypt_mac = true;
    if(flag == 1) {
        handshake = true;
        char *private_key_file = argv[3];
        char *certificate_file = argv[4];

        // load private key & certificate
        load_private_key(private_key_file);
        load_certificate(certificate_file);
    }

    while (true) {
        
        // retransmission from rto
        // if (timer_active) {
        //     struct timeval now;
        //     gettimeofday(&now, NULL);
        //     double elapsed_time = (now.tv_sec - timer_start.tv_sec) + (now.tv_usec - timer_start.tv_usec) / 1e6;
        //     // timer expired
        //     if (elapsed_time >= RTO) {
        //         // retransmit leftmost unacked packet if not NULL
        //         Packet* retransmit = input_window[input_left];
        //         if (retransmit) {
        //             fprintf(stderr, "Retransmitting packet with size: %ld\n", sizeof(Packet) + ntohs(retransmit->payload_size));
        //             int did_send = sendto(sockfd, retransmit, sizeof(Packet) + ntohs(retransmit->payload_size), 0, (struct sockaddr *)&clientaddr, clientsize);
        //             if (did_send < 0) {
        //                 perror("Retransmit failed");
        //             }
        //         }
        //         // reset timer
        //         gettimeofday(&timer_start, NULL);
        //     }
        // }

        //security handshake
        if(handshake) { //if handshake still ongoing
            if(input_left == 1 && server_window[1] != NULL && input_window[1] == NULL){//can only make server hello if we recieve client hello and input window 0 is null
                fprintf(stderr, "RECEIVE CLIENT HELLO\n");
                Packet* client_hello_packet = server_window[1];
                ClientHello *client_hello = (ClientHello *) client_hello_packet -> data;
                uint8_t client_comm_type = client_hello->comm_type;
                uint8_t client_nonce[32] = {0};
                memcpy(client_nonce, client_hello->client_nonce, 32);

                // create & send server hello
                Packet* server_hello = create_server_hello(client_comm_type, client_nonce);
                input_window[1] = server_hello;
                ServerHello* srvh = (ServerHello*) input_window[1] -> data; 
                fprintf(stderr, "server hello size %ld\n", sizeof(Packet) + server_hello -> payload_size);

                sendto(sockfd, server_hello, sizeof(Packet) + server_hello -> payload_size, 0, (struct sockaddr *)&clientaddr, sizeof(clientaddr));
                fprintf(stderr, "SENT SERVER HELLO\n");

                curr_packet_num += 1;
                free(server_window[1]);
                server_window[1] = NULL;
                // fprintf(stderr, "Sleft pointer: %d\n", left_pointer);
                left_pointer += 1;
            }
            else if(input_left == 2 && server_window[2] != NULL && input_window[2] == NULL){ //this means we have recieved 2nd ack + key exchange, need to parse it
                fprintf(stderr, "RECEIVED KEY EXCHANGE\n");
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

                // create & send fin message
                Packet* server_fin = create_fin();
                input_window[2] = server_fin;
                int did_send = sendto(sockfd, server_fin, sizeof(Packet) + server_fin -> payload_size , 0, (struct sockaddr *)&clientaddr, clientsize);
                if (did_send < 0) {
                    perror("Failed to send server fin msg");
                }
                fprintf(stderr, "SENT FIN\n");

                curr_packet_num += 1;
                free(server_window[2]);
                server_window[2] = NULL;
                left_pointer += 1;
            }
        }

        // listen to socket for incoming data from client
        char client_buf[BUF_SIZE];
        socklen_t clientsize = sizeof(clientaddr);
        int bytes_recvd = recvfrom(sockfd, client_buf, BUF_SIZE, 0, (struct sockaddr*) &clientaddr, &clientsize);
        
        if (bytes_recvd > 0) {
            fprintf(stderr, "incoming packet from client\n");
            Packet* received_packet = (Packet*)client_buf;
            uint32_t received_packet_number = ntohl(received_packet->packet_number);
            uint32_t received_ack_number = ntohl(received_packet->acknowledgment_number);
            uint16_t received_payload_size = ntohs(received_packet->payload_size);
            
            fprintf(stderr, "received ack #: %d\n", received_ack_number);
            fprintf(stderr, "received packet #: %d\n", received_packet_number);
            fprintf(stderr, "received payload size: %d\n", received_payload_size);

            // receive an ack --> update input window
            if (received_ack_number != 0) {
                fprintf(stderr, "received ack: %d\n", received_ack_number);
                
                // receive ack for fin
                if (handshake && received_ack_number == 3) {
                    fprintf(stderr, "RECEIVED FIN ACK\n");
                    handshake = false;
                    if (encrypt_mac) {
                        derive_keys();

                        fprintf(stderr, "Encryption key: %.*s\n", SECRET_SIZE, enc_key);
                        fprintf(stderr, "Authentication key: %.*s\n", SECRET_SIZE, mac_key);
                    }
                }

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
                        fprintf(stderr, "no unacked packets in window\n");
                        timer_active = false;
                    } 
                    // reset timer otherwise
                    else {
                        gettimeofday(&timer_start, NULL);
                    }
                }
            }
            
            // receive data --> send an ack
            if (received_packet_number != 0) {
                // Update window to reflect new packet
                // fprintf(stderr, "help%d\n", received_packet_number);
                server_window[received_packet_number] = (Packet*)malloc(sizeof(Packet) + received_payload_size);
                if (server_window[received_packet_number] == NULL) {
                    perror("Memory allocation failed");
                    close(sockfd);
                    return 1;
                }
                // send ACK
                memcpy(server_window[received_packet_number], received_packet, sizeof(Packet) + received_payload_size);
        
                // Update left pointer until it points to nothing, adjust right pointer too
                if(!handshake){
                    while (server_window[left_pointer] != NULL) {
                        uint8_t *payload = received_packet->data;
                        // decrypt data
                        if (flag == 1) {
                            fprintf(stderr, "receive encrypted data\n");
                            EncryptedData* encrypted = (EncryptedData*) payload;
                            uint16_t encrypted_data_size = encrypted->payload_size;
                            // data will be payload - mac size if no encrypt mac
                            if (encrypt_mac) {
                                encrypted_data_size = encrypted->payload_size - MAC_SIZE;
                            }
                            char* encrypted_data = (char*) malloc (encrypted_data_size);
                            memcpy(encrypted_data, encrypted->data, encrypted_data_size);
                            fprintf(stderr, "encrypted size %d: \n", encrypted_data_size);
                            
                            char iv[IV_SIZE];
                            memcpy(iv, (char*) encrypted->init_vector, IV_SIZE);
                            
                            char decrypted_data[encrypted_data_size];
                            size_t size = decrypt_cipher(encrypted_data, encrypted_data_size, iv, decrypted_data, 0);
                            // fprintf(stderr, "decrypted size %ld: \n", size);
                            // fprintf(stderr, "Decrypted plaintext: %.*s\n", (int) size, decrypted_data);

                            // input_size = output_size - padding #
                            unsigned char padding_size = decrypted_data[encrypted_data_size - 1];

                            // verify the packet MAC
                            if (encrypt_mac) {
                                char* mac_code = (char*) malloc (MAC_SIZE);
                                memcpy(mac_code, encrypted->data + encrypted_data_size, MAC_SIZE);

                                if (!verify((char *) decrypted_data, size - padding_size, (char*) mac_code, MAC_SIZE, ec_peer_public_key)) {
                                    fprintf(stderr, "Verification of packet mac code failed.\n");
                                    free(mac_code);
                                    close(sockfd);
                                    exit(EXIT_FAILURE);
                                }
                                fprintf(stderr, "Verification of packet mac code succeeded.\n");
                                free(mac_code);
                            }

                            write(1, decrypted_data, size - padding_size);

                            free(encrypted_data);
                        }
                        // not encrypted data
                        else {
                            fprintf(stdout, "%.*s", received_payload_size, payload);
                        }
                        if (server_window[left_pointer] != NULL) {
                            free(server_window[left_pointer]);
                            server_window[left_pointer] = NULL;
                        }
                        left_pointer += 1;
                        if (left_pointer < MAX_PACKET_SEND_SIZE - 20) {
                            right_pointer += 1;
                        }
                    }

                    // check whether there is data from input to send as well as ack
                    Packet* new_packet = read_from_stdin(flag, encrypt_mac, input_window, curr_packet_num, input_left, input_right, timer_active, timer_start);

                     // if not, send pure ack packet
                    if (new_packet == NULL) {
                        send_ACK(received_packet_number + 1, sockfd, clientaddr);
                    }
                    // send data + ack
                    else {
                        input_window[curr_packet_num] = new_packet;
                        curr_packet_num += 1;

                        new_packet->acknowledgment_number = htonl(left_pointer);

                        // send the packet
                        int did_send = sendto(sockfd, new_packet, sizeof(Packet) + new_packet->payload_size, 0, (struct sockaddr *)&clientaddr, sizeof(clientaddr));
                        if (did_send < 0) return errno;

                        // reset timer
                        if (!timer_active) {
                            timer_active = true;
                            gettimeofday(&timer_start, NULL);
                        }
                    }
                    // Now we can send the cumulative ack
                    // send_ACK(left_pointer, sockfd, clientaddr);
                }
                else{
                    fprintf(stderr, "revd pack num%d\n",received_packet_number );
                    send_ACK(received_packet_number + 1, sockfd, clientaddr);
                }
            } 
        }

        // no bytes received, just send whatever is in standard input
        if (!handshake) {
            // printf("HER\n");
            Packet* new_packet = read_from_stdin(flag, encrypt_mac, input_window, curr_packet_num, input_left, input_right, timer_active, timer_start);
            
            // send the packet
            if (new_packet != NULL) {
                int did_send = sendto(sockfd, new_packet, sizeof(Packet) + ntohs(new_packet->payload_size), 0, (struct sockaddr *)&clientaddr, sizeof(clientaddr));
                if (did_send < 0) return errno;
                
                curr_packet_num += 1;

                // reset timer
                if (!timer_active) {
                    timer_active = true;
                    gettimeofday(&timer_start, NULL);
                }
            }
        }
    }
    /* 8. You're done! Terminate the connection */     
    close(sockfd);
    return 0;
}

Packet* read_from_stdin(int flag, bool encrypt_mac, Packet* input_window[], int &curr_packet_num, int input_left, int input_right, bool &timer_active, struct timeval &timer_start) {
    char read_buf[BUF_SIZE];
    memset(read_buf, 0, BUF_SIZE);
    // read MAX_SEG_SIZE from stdin at a time
    ssize_t bytesRead = 0;
    if (flag == 1 && encrypt_mac) {
        bytesRead = read(STDIN_FILENO, read_buf, 959);
    } 
    else if (flag == 1 && !encrypt_mac) {
        bytesRead = read(STDIN_FILENO, read_buf, 991);
    } 
    else {
        bytesRead = read(STDIN_FILENO, read_buf, MAX_SEGMENT_SIZE);
    }
    // check if we're within the send window
    if (bytesRead > 0 && curr_packet_num >= input_left && curr_packet_num <= input_right) {
        fprintf(stderr, "bytes read from stdin %ld\n", bytesRead);
        fprintf(stderr, "current packet num %d\n", curr_packet_num);

        // create a new packet
        Packet* new_packet = (Packet*)malloc(sizeof(Packet) + bytesRead);
        new_packet->packet_number = curr_packet_num;
        new_packet->acknowledgment_number = 0;

        // encrypt data 
        if (flag == 1) {
            fprintf(stderr, "ENCRYPT DATA\n");
            // output_size = input_size + (block_size - (input_size % block_size))

            size_t block_size = EVP_CIPHER_block_size(EVP_aes_256_cbc());
            size_t cipher_buf_size = bytesRead + (block_size - (bytesRead % block_size));
            fprintf(stderr, "cipher buf size: %ld \n", cipher_buf_size);
            char *cipher = (char *)malloc(cipher_buf_size);
            char iv[IV_SIZE];
            
            // BUGGY -- SEGFAULT / INVALID POINTER ERROR HAPPENS HERE
            size_t cipher_size = encrypt_data(read_buf, bytesRead, iv, cipher, 0);
            fprintf(stderr, "cipher size: %ld \n", cipher_size);

            // BUGGY -- DOUBLE FREE / INVALID POINTER HAPPENS SOMEWHERE HERE

            // create encrypted data message
            // no mac 
            if (!encrypt_mac) {
                EncryptedData* encrypt_data = (EncryptedData*)malloc(sizeof(EncryptedData) + cipher_size);
                encrypt_data->payload_size = cipher_size;
                encrypt_data->padding = 0;
                memcpy(encrypt_data->init_vector, iv, IV_SIZE);
                memcpy(encrypt_data->data, cipher, cipher_size);

                encrypt_data -> header.msg_type = DATA; 
                encrypt_data -> header.padding = 0; 
                encrypt_data -> header.msg_len = sizeof(EncryptedData) + cipher_size + MAC_SIZE - sizeof(SecurityHeader);

                // populate udp packet
                new_packet->payload_size = sizeof(EncryptedData) + cipher_size;
                memcpy(new_packet->data, encrypt_data, sizeof(EncryptedData) + cipher_size);
                
                free(cipher);
                free(encrypt_data);
            }
            // mac (so hungry i need a big mac rn)
            // this is causing me to lose braincells.
            else {
                EncryptedData* encrypt_data = (EncryptedData*)malloc(sizeof(EncryptedData) + cipher_size + MAC_SIZE);
                encrypt_data->payload_size = cipher_size + MAC_SIZE;
                encrypt_data->padding = 0;
                memcpy(encrypt_data->init_vector, iv, IV_SIZE);
                memcpy(encrypt_data->data, cipher, cipher_size);

                // hmac over the iv + encrypted payload
                size_t total_size = IV_SIZE + cipher_size;
                char *concatenated_data = (char *)malloc(total_size);
                memcpy(concatenated_data, iv, IV_SIZE);
                memcpy(concatenated_data + IV_SIZE, cipher, cipher_size);
                char mac[MAC_SIZE];
                hmac(concatenated_data, total_size, mac);
                memcpy(encrypt_data->data + cipher_size, mac, MAC_SIZE);
                fprintf(stderr, "HMAC over data: %.*s\n", MAC_SIZE, mac);
                encrypt_data -> header.msg_type = DATA; 
                encrypt_data -> header.padding = 0; 
                encrypt_data -> header.msg_len = sizeof(EncryptedData) + cipher_size + MAC_SIZE - sizeof(SecurityHeader); 

                // populate udp packet
                new_packet->payload_size = sizeof(EncryptedData) + cipher_size + MAC_SIZE;
                memcpy(new_packet->data, encrypt_data, sizeof(EncryptedData) + cipher_size + MAC_SIZE);
                
                // free(cipher);
                // free(encrypt_data);
            }
        }
        // non-encrypted data
        else {
            new_packet->payload_size = bytesRead;
            memcpy(new_packet->data, read_buf, bytesRead);
        }

        return new_packet;
    }
    return NULL;
}

// send fin message to client
Packet *create_fin() {
    Finished* server_fin = (Finished*)malloc(sizeof(Finished));
    server_fin -> header.msg_type = FINISHED; 
    server_fin -> header.padding = 0; 
    server_fin -> header.msg_len = sizeof(Finished) - sizeof(SecurityHeader); 
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
    // packet->padding = 0;
    memcpy(packet->data, server_fin, sizeof(Finished));

    fprintf(stderr, "size of fin packet: %d\n", packet->payload_size);

    // Free the temporary Finished message memory
    free(server_fin);
    return packet;
}

// send ServerHello message back to client
Packet *create_server_hello(int comm_type, uint8_t *client_nonce){
    size_t sig_size = sign((char*)client_nonce, 32, NULL);

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

    FILE *file = fopen("public_key.txt", "w");


    // Write the data into the file
    for (size_t i = 0; i < 95; i++) {
        fprintf(file, "%02hhX ", (unsigned char)server_hello->data[i]);
    }
    fclose(file);

    char *server_nonce_sig = (char*)malloc(sig_size);
    sign((char*)client_nonce, 32, server_nonce_sig);
    FILE *nonce = fopen("actual_signed_nonce.txt", "w");
    // Write the server public key data into the file
    for (size_t i = 0; i < sig_size; i++) {
        fprintf(nonce, "%02hhX ", (unsigned char)server_nonce_sig[i]);
    }
    fclose(nonce);
    memcpy(server_hello->data + cert_size, server_nonce_sig, sig_size);
    fprintf(stderr, "sig size %ld\n", cert_size + sig_size);   

    server_hello->sig_size = sig_size;
    free(server_nonce_sig);
    server_hello -> header.msg_len = sizeof(ServerHello) + sizeof(Certificate) + cert_size + sig_size - sizeof(SecurityHeader);

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