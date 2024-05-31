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
#define MAX_SEGMENT_SIZE 1024 // payload size for each packet (bytes)
#define MAX_PACKET_SEND_SIZE 2001
#define RTO 1 // retransmission timer

// Function prototypes
void send_ACK(uint32_t left_window_index, int sockfd, struct sockaddr_in serveraddr);
Packet *create_client_hello(char* client_nonce_buf);
Packet *create_key_exchange(char *client_nonce, char *server_nonce, char *signed_nonce, size_t signed_nonce_size, Certificate *server_cert, int sockfd, struct sockaddr_in serveraddr);
Packet* read_from_stdin(int flag, bool encrypt_mac, Packet* input_window[], int &curr_packet_num, int input_left, int input_right, bool &timer_active, struct timeval &timer_start);

int main(int argc, char *argv[])
{
    // Parse the arguments
    // if (argc < 5)
    // {
    //     std::cerr << "Usage: " << argv[0] << " <flag> <hostname> <port> <ca_public_key_file>\n";
    //     return 1;
    // }

    int flag = atoi(argv[1]);
    char *hostname = argv[2];
    int port = atoi(argv[3]);

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
   
    uint8_t client_nonce_buf[32] = {0};

    struct timeval timer_start;

    // security stuff
    bool handshake = false;
    bool encrypt_mac = true;
    if (flag == 1) {
        handshake = true;
        char *ca_public_key_file = argv[4];

        // Load CA public key
        load_ca_public_key(ca_public_key_file);
    }

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
                    //fprintf(stderr, "Retransmitting packet with size: %ld\n", sizeof(Packet) + ntohs(retransmit->payload_size));
                    int did_send = sendto(sockfd, retransmit, sizeof(Packet) + ntohs(retransmit->payload_size), 0, (struct sockaddr *)&serveraddr, serversize);
                    if (did_send < 0) {
                        perror("Retransmit failed");
                    }
                }
                // reset timer
                gettimeofday(&timer_start, NULL);
            }
        }

        //security handshake
        if(handshake){ // start handshake, assume acks are incrementing curr pack num
            if(curr_packet_num == 1 && input_window[1] == NULL){
                input_window[curr_packet_num] = create_client_hello((char*) client_nonce_buf); //create client hello if not yet created
                sendto(sockfd, input_window[curr_packet_num], sizeof(ClientHello), 0, (struct sockaddr *)&serveraddr, serversize); //send packet
                curr_packet_num += 1;
                //fprintf(stderr, "SENT CLIENT HELLO\n");
            }
            else if(curr_packet_num == 2 && server_window[1] != NULL && input_window[2] == NULL){ //create the exchange message if recieved an serverhello/ack from server, server send the hello, and input window null
                //fprintf(stderr, "RECEIVED SERVER HELLO\n");
                Packet* server_hello_packet = server_window[1];
                ServerHello *server_hello = (ServerHello *) server_hello_packet -> data;
                SecurityHeader* header = &server_hello -> header;
                if (header->msg_type != SERVER_HELLO) {
                    //fprintf(stderr, "Expected SERVER_HELLO, but got message type: %u\n", header->msg_type);
                    close(sockfd);
                    return 1;
                }
                uint8_t server_comm_type = server_hello->comm_type;
                uint8_t server_sig_size = (server_hello->sig_size);
                
                // extract server certificate
                uint16_t server_cert_size = server_hello->cert_size;
                // Check if the server certificate size is valid
                if (server_cert_size == 0) {
                    //fprintf(stderr, "Invalid server certificate size: %u\n", server_cert_size);
                    close(sockfd);
                    exit(EXIT_FAILURE);
                }
                uint8_t raw_cert_buf[server_cert_size];
                memcpy(raw_cert_buf, server_hello->data, server_cert_size);
                
                Certificate* server_cert = (Certificate*) raw_cert_buf;
                int key_len = ntohs(server_cert->key_len);
                //fprintf(stderr, "certificate key length HERE%d\n", key_len);
                //fprintf(stderr, "certificate length %u\n", server_cert_size);
                //fprintf(stderr, "signature length %d\n", server_sig_size);

                uint8_t server_nonce[32] = {0};
                memcpy(server_nonce, server_hello->server_nonce, 32);
                //fprintf(stderr, "server nonce length %ld\n", sizeof(server_nonce));

                // extract server signature
                char* client_nonce_signed = (char*) malloc (server_sig_size);
                memcpy(client_nonce_signed, server_hello->data + sizeof(Certificate), server_sig_size);

                uint8_t* pub_key = (uint8_t*)malloc(key_len);
                if (pub_key == NULL) {
                    //fprintf(stderr, "Memory allocation failed for client nonce signed.\n");
                    close(sockfd);
                    exit(EXIT_FAILURE);
                }
                memcpy(pub_key, server_cert->data, key_len);
                free(pub_key);
                // DEFINTION:
                // Packet *create_key_exchange(
                //char* client_nonce, 
                // char *server_nonce, 
                // char *signed_nonce, // server signature of client nonce
                // size_t signed_nonce_size, // size of signed_nonce
                // Certificate* server_cert, 
                // int sockfd, 
                // struct sockaddr_in serveraddr)

                // Close the file for server public key
                Packet *key_exchange_packet = create_key_exchange(
                (char*) client_nonce_buf,
                (char*) server_nonce, 
                    client_nonce_signed, 
                    server_sig_size,
                    server_cert, 
                    sockfd, 
                    serveraddr
                );
                input_window[curr_packet_num] = key_exchange_packet;
                // Calculate the total size of the packet to send
                size_t packet_size = sizeof(Packet) + key_exchange_packet->payload_size;
                // Send the packet
                sendto(sockfd, key_exchange_packet, packet_size, 0, (struct sockaddr *)&serveraddr, serversize);

                free(client_nonce_signed);

                curr_packet_num += 1;
                free(server_window[1]);
                server_window[1] = NULL;
                left_pointer += 1;
                //fprintf(stderr, "SENT KEY EXCHANGE\n");
            }
        }

        // listen to socket for incoming packets from server
        char server_buf[BUF_SIZE];
        int bytes_recvd = recvfrom(sockfd, server_buf, BUF_SIZE, 0, (struct sockaddr*)&serveraddr, &serversize);
        
        if (bytes_recvd > 0) {
            printf("incoming packet from server\n");
            Packet* received_packet = (Packet*)server_buf;
            uint32_t received_packet_number = ntohl(received_packet->packet_number);
            uint32_t received_ack_number = ntohl(received_packet->acknowledgment_number);
            uint16_t received_payload_size = ntohs(received_packet->payload_size);
            
            //fprintf(stderr, "received ack #: %d\n", received_ack_number);
            //fprintf(stderr, "received packet #: %d\n", received_packet_number);
            //fprintf(stderr, "received payload size: %d\n", received_payload_size);

            // receive an ack --> update input window
            if (received_ack_number != 0) {
                //fprintf(stderr, "received ack: %d\n", received_ack_number);
                // if(received_ack_number == 3 && handshake){
                //     handshake = false;
                // }
                if (received_ack_number > input_left) {
                    // free packets from input_left to ack #
                    for (int i = input_left; i < received_ack_number; i++) {
                        if (input_window[i] != NULL) {
                            //fprintf(stderr, "HAHAHA\n");
                            free(input_window[i]);
                            
                            input_window[i] = NULL;
                        }
                    }
                    //fprintf(stderr, "HAHAHA2\n");
                    input_left = received_ack_number;
                    input_right = 20 + input_left;
                    // //fprintf(stderr, "input right: %d\n", input_right);

                    // cancel timer if no unacked packets
                    if (input_left == curr_packet_num) {
                        //fprintf(stderr, "no unacked packets in window\n");
                        timer_active = false;
                    } 
                    // reset timer otherwise
                    else {
                        gettimeofday(&timer_start, NULL);
                    }
                }
            }

            // also receive data --> send an ack
            if (received_packet_number != 0) {
                // Update window to reflect new packet
                // //fprintf(stderr, "RECEIVE DATA (NON ACK) %d\n", received_packet_number);
                server_window[received_packet_number] = (Packet*)malloc(sizeof(Packet) + received_payload_size);
                if (server_window[received_packet_number] == NULL) {
                    perror("Memory allocation failed");
                    close(sockfd);
                    return 1;
                }
                
                // copy received packet to server window buffer
                memcpy(server_window[received_packet_number], received_packet, sizeof(Packet) + received_payload_size);

                // Update left pointer until it points to nothing, adjust right pointer too
                if(!handshake){
                    while (server_window[left_pointer] != NULL) {
                        uint8_t *payload = received_packet->data;
                        // decrypt data
                        if (flag == 1) {
                            //fprintf(stderr, "receive encrypted data\n");
                            EncryptedData* encrypted = (EncryptedData*) payload;
                            uint16_t encrypted_data_size = encrypted->payload_size;
                            // data will be payload - mac size if no encrypt mac
                            if (encrypt_mac) {
                                encrypted_data_size = encrypted->payload_size - MAC_SIZE;
                            }
                            char* encrypted_data = (char*) malloc (encrypted_data_size);
                            memcpy(encrypted_data, encrypted->data, encrypted_data_size);
                            // //fprintf(stderr, "encrypted size %d: \n", encrypted_data_size);
                            
                            char iv[IV_SIZE];
                            memcpy(iv, (char*) encrypted->init_vector, IV_SIZE);
                            
                            char decrypted_data[encrypted_data_size];
                            size_t size = decrypt_cipher(encrypted_data, encrypted_data_size, iv, decrypted_data, 0);
                            // //fprintf(stderr, "Decrypted plaintext: %.*s\n", (int) size, decrypted_data);

                            unsigned char padding_size = decrypted_data[encrypted_data_size - 1];

                            // verify the packet MAC
                            if (encrypt_mac) {
                                char* mac_code = (char*) malloc (MAC_SIZE);
                                memcpy(mac_code, encrypted->data + encrypted_data_size, MAC_SIZE);

                                if (!verify((char *) decrypted_data, size - padding_size, (char*) mac_code, MAC_SIZE, ec_peer_public_key)) {
                                    //fprintf(stderr, "Verification of packet mac code failed.\n");
                                    free(mac_code);
                                    close(sockfd);
                                    exit(EXIT_FAILURE);
                                }
                                //fprintf(stderr, "Verification of packet mac code succeeded.\n");
                                free(mac_code);
                            }

                            write(1, decrypted_data, size - padding_size);

                            free(encrypted_data);
                        }
                        // not encrypted data
                        else {
                            //fprintf(stdout, "%.*s", received_payload_size, payload);
                            fflush(stdout);
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
                        send_ACK(received_packet_number + 1, sockfd, serveraddr);
                    }
                    // send data + ack
                    else {
                        input_window[curr_packet_num] = new_packet;
                        curr_packet_num += 1;

                        new_packet->acknowledgment_number = htonl(left_pointer);

                        // send the packet
                        int did_send = sendto(sockfd, new_packet, sizeof(Packet) + new_packet->payload_size, 0, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
                        if (did_send < 0) return errno;

                        // reset timer
                        if (!timer_active) {
                            timer_active = true;
                            gettimeofday(&timer_start, NULL);
                        }
                    }
                    // Now we can send the cumulative ack
                    // send_ACK(left_pointer, sockfd, serveraddr);
                }
                // receive fin 
                else {
                    if (curr_packet_num == 3) {
                        //fprintf(stderr, "RECEIVED FIN \n");
                        handshake = false;
                        if (encrypt_mac) {
                            derive_keys();

                            //fprintf(stderr, "Encryption key: %.*s\n", SECRET_SIZE, enc_key);
                            //fprintf(stderr, "Authentication key: %.*s\n", SECRET_SIZE, mac_key);
                        }
                        free(server_window[2]);
                        server_window[2] = NULL;
                        left_pointer += 1;
                    }
                    send_ACK(received_packet_number + 1, sockfd, serveraddr);
                }
            }
        }

        // no packets received, just send whatever is in standard input
        if (!handshake) {
            Packet* new_packet = read_from_stdin(flag, encrypt_mac, input_window, curr_packet_num, input_left, input_right, timer_active, timer_start);
            
            // send the packet
            if (new_packet != NULL) {
                int did_send = sendto(sockfd, new_packet, sizeof(Packet) + ntohs(new_packet->payload_size), 0, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
                //fprintf(stderr, "did_send size %d: \n", did_send);
                if (did_send < 0) return errno;

                curr_packet_num += 1;

                // reset timer
                if (!timer_active) {
                    timer_active = true;
                    gettimeofday(&timer_start, NULL);
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

Packet* read_from_stdin(int flag, bool encrypt_mac, Packet* input_window[], int &curr_packet_num, int input_left, int input_right, bool &timer_active, struct timeval &timer_start) {
    char read_buf[BUF_SIZE];
    memset(read_buf, 0, BUF_SIZE);
    // read MAX_SEG_SIZE from stdin at a time
    int bytesRead = 0;
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
        //fprintf(stderr, "bytes read from stdin %d\n", bytesRead);
        //fprintf(stderr, "current packet num %d\n", curr_packet_num);
    
        // Print the contents of read_buf
        // //fprintf(stderr, "read_buf contents:\n");
        // for (ssize_t i = 0; i < bytesRead; ++i) {
        //     //fprintf(stderr, "%c", read_buf[i]);
        // }
        // //fprintf(stderr, "\n");

        // create a new packet
        Packet* new_packet = (Packet*)malloc(sizeof(Packet) + bytesRead);
        new_packet->packet_number = htonl((uint32_t) curr_packet_num);
        new_packet->acknowledgment_number = htonl((uint32_t)0);

        // encrypt data 
        if (flag == 1) {
            //fprintf(stderr, "ENCRYPT DATA\n");
            // output_size = input_size + (block_size - (input_size % block_size))

            size_t block_size = EVP_CIPHER_block_size(EVP_aes_256_cbc());
            size_t cipher_buf_size = bytesRead + (block_size - (bytesRead % block_size));
            //fprintf(stderr, "cipher buf size: %ld \n", cipher_buf_size);
            char *cipher = (char *)malloc(cipher_buf_size);
            char iv[IV_SIZE];
            
            // BUGGY -- SEGFAULT / INVALID POINTER ERROR HAPPENS HERE
            size_t cipher_size = encrypt_data(read_buf, bytesRead, iv, cipher, 0);
            //fprintf(stderr, "cipher size: %ld \n", cipher_size);

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
                //fprintf(stderr, "HMAC over data: %.*s\n", MAC_SIZE, mac);
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
            new_packet->payload_size = htons((uint16_t)bytesRead);
            memcpy(new_packet->data, read_buf, bytesRead);
        }

        return new_packet;
    }
    return NULL;
}

// Sends cumulative ACK depending on the packet number received
void send_ACK(uint32_t left_window_index, int sockfd, struct sockaddr_in serveraddr) {
    Packet ack_packet = {0};
    ack_packet.acknowledgment_number = htonl(left_window_index);
    sendto(sockfd, &ack_packet, sizeof(ack_packet), 0, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
}

Packet *create_client_hello(char* client_nonce_buf){
    ClientHello* client_hello = (ClientHello*)malloc(sizeof(ClientHello));
    if (client_hello == nullptr) {
        //fprintf(stderr, "Memory allocation failed for ClientHello.\n");
        return nullptr;
    }
    // Initialize comm_type based on flag
    client_hello->comm_type = 1; 
    // Initialize padding to zero
    client_hello->padding = 0; 
    // Generate client nonce
    // char client_nonce_buf[32]; // 32 bytes for the nonce
    generate_nonce(client_nonce_buf, 32); // fill nonce_buf with 32 bytes of data
    memcpy(client_hello->client_nonce, client_nonce_buf, 32);

    client_hello -> header.msg_type = CLIENT_HELLO; 
    client_hello -> header.padding = 0; 
    client_hello -> header.msg_len = sizeof(ClientHello) - sizeof(SecurityHeader); 
    //fprintf(stderr, "ch size %ld\n", sizeof(client_hello) - sizeof(SecurityHeader));
    Packet *packet = (Packet *)malloc(sizeof(Packet) + sizeof(client_hello));
    if (packet == nullptr) {
        //fprintf(stderr, "Memory allocation failed for Packet.\n");
        free(client_hello);
        return nullptr;
    }
    memcpy(packet->data, client_hello, sizeof(client_hello));

    packet->packet_number = 1;
    packet->acknowledgment_number = 0;
    packet->payload_size = sizeof(client_hello); //flag for later
    free(client_hello); // Free the memory allocated for ClientHello since it's copied into packet
    return packet;
}

Packet *create_key_exchange(char* client_nonce, char *server_nonce, char *signed_nonce, size_t signed_nonce_size, Certificate* server_cert, int sockfd, struct sockaddr_in serveraddr) {
    load_peer_public_key((char*) server_cert->data, server_cert->key_len);
    if(ec_peer_public_key == NULL){
        //fprintf(stderr, "errrrrm what the sigma\n");
    }

    uint16_t key_len = ntohs(server_cert -> key_len);
    uint8_t *server_public_key = server_cert -> data;
    size_t signature_len = cert_size - (2 * sizeof(uint16_t) + key_len);
    uint8_t *signature = server_public_key + key_len;
    //fprintf(stderr, "server cert key len %d\n", key_len);
    // Verify server signature inside of the certificate
    if (!verify((char *) server_public_key, key_len, (char*) signature, signature_len, ec_ca_public_key)) {
        //fprintf(stderr, "Verification of server certificate failed.\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    if (!verify((char*) client_nonce, 32, (char*)signed_nonce, signed_nonce_size, ec_peer_public_key)) {
        //fprintf(stderr, "Verification of signature failed.\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }


    generate_private_key(); //now private key is stored in private key var 
    derive_public_key(); //now public key is stored in variable "public_key"
    derive_secret();  //now secret variable has the private key
    
    //now we need to create a certificate and sign the certificate with our own private key

    // Calculate the size needed for the public key signature
    size_t self_signature_size = sign((char*)public_key, sizeof(public_key), NULL);
    // Allocate memory for client certificate
    Certificate* client_cert = (Certificate*)malloc(sizeof(Certificate) + pub_key_size + self_signature_size);
    if (client_cert == NULL) {
        //fprintf(stderr, "Failed to allocate memory for client certificate.\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    // Initialize client_cert
    client_cert -> key_len = pub_key_size; 
    client_cert -> padding = 0;
    memcpy(client_cert->data, public_key, pub_key_size); 

    size_t self_sig_size = sign((char*)public_key, sizeof(public_key), NULL);
    char *self_signature = (char*)malloc(self_sig_size);
    sign((char*)public_key, sizeof(public_key), self_signature);
    memcpy(client_cert->data + pub_key_size, self_signature, self_sig_size);
    free(self_signature); 

    //now we have to sign the server nonce
    size_t nonce_signature_size = sign((char*)server_nonce, sizeof(server_nonce), NULL);
    char *nonce_signature = (char*)malloc(nonce_signature_size);
    sign((char*)client_nonce, sizeof(*client_nonce), nonce_signature);

    if (nonce_signature == NULL) {
        //fprintf(stderr, "Failed to sign the server nonce.\n");
        free(nonce_signature);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    //now create the keyexchage packet
    KeyExchangeRequest* key_exchange = (KeyExchangeRequest*) malloc(sizeof(KeyExchangeRequest) + sizeof(Certificate) + pub_key_size + self_signature_size + nonce_signature_size);
    // size of signature & certificate
    key_exchange -> sig_size = nonce_signature_size; 
    key_exchange -> cert_size = sizeof(Certificate) + self_signature_size + pub_key_size;
    // copy certificate into data
    memcpy(key_exchange->data, client_cert, sizeof(Certificate) + pub_key_size + self_signature_size); 
    // copy signature of server nonce into data
    memcpy(key_exchange->data + key_exchange -> cert_size, nonce_signature, nonce_signature_size); 
    
    key_exchange -> header.msg_type = KEY_EXCHANGE_REQUEST; 
    key_exchange -> header.padding = 0; 
    key_exchange -> header.msg_len = sizeof(key_exchange) - sizeof(SecurityHeader) + nonce_signature_size + sizeof(Certificate) + pub_key_size + self_signature_size; //may be wrong
    Packet *packet = (Packet *)malloc(sizeof(Packet) + key_exchange -> header.msg_len);
    if (packet == nullptr) {
        //fprintf(stderr, "Memory allocation failed for Packet.\n");
        free(key_exchange);
        return nullptr;
    }
    memcpy(packet->data, key_exchange, sizeof(KeyExchangeRequest) + sizeof(Certificate) + key_exchange -> cert_size + key_exchange -> sig_size);
    packet->packet_number = 2; // You may need to set this accordingly
    packet->acknowledgment_number = 0; // You may need to set this accordingly
    packet->payload_size = key_exchange -> header.msg_len;

    free(nonce_signature);
    free(key_exchange);
    return packet; 
}
