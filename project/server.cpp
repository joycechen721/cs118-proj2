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
Packet *create_server_hello(int comm_type, uint8_t *client_nonce, uint8_t *server_nonce_buf);
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
    int flags2 = fcntl(STDIN_FILENO, F_GETFL);
    flags2 |= O_NONBLOCK;
    fcntl(STDIN_FILENO, F_SETFL, flags2);

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
    int input_right = 20;

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
    uint8_t server_nonce_buf[32];
    while (true) {
        
        // retransmission from rto
        if (timer_active && flag == 0) {
            struct timeval now;
            gettimeofday(&now, NULL);
            double elapsed_time = (now.tv_sec - timer_start.tv_sec) + (now.tv_usec - timer_start.tv_usec) / 1e6;
            // timer expired
            if (elapsed_time >= RTO) {
                // retransmit leftmost unacked packet if not NULL

                // FROM RAWR: Add 1 to left pointer for retransmit
                Packet* retransmit = input_window[input_left];
                fprintf(stderr, "SERVER RETR PACK %d\n", input_left);
                if (retransmit) {
                    //fprintf(stderr, "Retransmitting packet with size: %ld\n", sizeof(Packet) + ntohs(retransmit->payload_size));
                    int did_send = sendto(sockfd, retransmit, sizeof(Packet) + ntohs(retransmit->payload_size), 0, (struct sockaddr *)&clientaddr, clientsize);
                    if (did_send < 0) {
                        perror("Retransmit failed");
                    }
                }
                // reset timer
                gettimeofday(&timer_start, NULL);
            }
        }

        //security handshake
        // if(handshake) { //if handshake still ongoing
            
        // }

        // listen to socket for incoming data from client
        char client_buf[BUF_SIZE + 12];
        socklen_t clientsize = sizeof(clientaddr);
        int bytes_recvd = recvfrom(sockfd, client_buf, BUF_SIZE + 12, 0, (struct sockaddr*) &clientaddr, &clientsize);
        
        if (bytes_recvd > 0) {
            if (!client_send) {
                client_send = true;
            }
            // fprintf(stderr, "incoming packet from client\n");
            Packet* received_packet = (Packet*)client_buf;
            
            uint32_t received_packet_number = ntohl(received_packet->packet_number);
            uint32_t received_ack_number = ntohl(received_packet->acknowledgment_number);
            uint16_t received_payload_size = ntohs(received_packet->payload_size);
            
            // fprintf(stderr, "received ack #: %d\n", received_ack_number);
            // fprintf(stderr, "received packet #: %d\n", received_packet_number);
            // fprintf(stderr, "received payload size: %d\n", received_payload_size);

            // receive an ack --> update input window
            if (received_ack_number != 0 || input_left == 1) {
                // fprintf(stderr, "SERVER received ack: %d\n", received_ack_number);
                
                // receive ack for fin
                if (handshake && received_ack_number == 2) {
                    fprintf(stderr, "RECEIVED FIN ACK\n");
                    handshake = false;
                    if (encrypt_mac) {
                        derive_keys();

                        // fprintf(stderr, "Encryption key: %.*s\n", SECRET_SIZE, enc_key);
                        //fprintf(stderr, "Authentication key: %.*s\n", SECRET_SIZE, mac_key);
                    }
                }

                if (received_ack_number >= input_left) {
                    // free packets from input_left to ack #
                    for (int i = input_left; i <= received_ack_number; i++) {
                        if (input_window[i] != NULL) {
                            // fprintf(stderr, "free input #: %d\n", i);
                            free(input_window[i]);
                            input_window[i] = NULL;
                        }
                    }
                    input_left = received_ack_number + 1;
                    input_right = 20 + input_left;

                    // cancel timer if no unacked packets
                    if (input_left == curr_packet_num) {
                        // fprintf(stderr, "no unacked packets in window\n");
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
                if (!handshake && flag == 1) {
                    EncryptedData* encrypted = (EncryptedData*) received_packet -> data;
                    uint16_t encrypted_data_size = ntohs(encrypted->payload_size);
                    // Allocate memory for the encrypted data plus IV_SIZE
                    char* encrypted_data = (char*) malloc(encrypted_data_size + IV_SIZE);
                    // Copy the IV and encrypted data from the payload
                    memcpy(encrypted_data, encrypted->init_vector, encrypted_data_size + IV_SIZE);
                    if (memcmp(encrypted_data, encrypted->init_vector , IV_SIZE) != 0){
                        fprintf(stderr, "verification failed\n");
                    }
                    // Verify the packet MAC if encryption with MAC is enabled
                    if (encrypt_mac) {
                        char* received_mac = (char*) encrypted->data + encrypted_data_size;
                        char computed_mac_code[32];
                        hmac(encrypted_data, encrypted_data_size + IV_SIZE, computed_mac_code);
                        // fprintf(stderr, "Received MAC: ");
                        // for (int i = 0; i < MAC_SIZE; i++) {
                        //     fprintf(stderr, "%02X ", (unsigned char)received_mac[i]);
                        // }
                        // fprintf(stderr, "\nComputed MAC: ");
                        // for (int i = 0; i < MAC_SIZE; i++) {
                        //     fprintf(stderr, "%02X ", (unsigned char)computed_mac_code[i]);
                        // 
                        if (memcmp(computed_mac_code, received_mac, MAC_SIZE) != 0) {
                            fprintf(stderr, "MAC code verification failed\n");
                            free(encrypted_data);
                            close(sockfd);
                            exit(EXIT_FAILURE);
                        }
                        // fprintf(stderr, "Verification of packet mac code succeeded.\n");
                    }

                    
                    // Free the allocated memory for encrypted data
                    free(encrypted_data);
                }
                server_window[received_packet_number] = (Packet*)malloc(sizeof(Packet) + received_payload_size);
                if (server_window[received_packet_number] == NULL) {
                    perror("Memory allocation failed");
                    close(sockfd);
                    return 1;
                }
                // copy received packet into server_window
                memcpy(server_window[received_packet_number], received_packet, sizeof(Packet) + received_payload_size);
                // Update left pointer until it points to nothing, adjust right pointer too
                if(!handshake){     
                    while (server_window[left_pointer] != NULL) {
                        // write all data in buffer (regardless of flag bc buffer contents should be unecrypted alr)
                        // write packet is leftmost packet in buffer
                        Packet *current_write_packet = (Packet*) server_window[left_pointer];
                        uint8_t* current_write_packet_data = current_write_packet -> data; 
                        // fprintf(stdout, "%.*s", received_payload_size, payload);
                        // fflush(stdout);
                        if(flag == 0){
                            write(STDOUT_FILENO, current_write_packet_data, ntohs(current_write_packet-> payload_size));
                        }
                        else{
                            EncryptedData* encrypted = (EncryptedData*) current_write_packet_data;
                            uint16_t encrypted_data_size = ntohs(encrypted->payload_size);
                            char iv[IV_SIZE];
                            memcpy(iv, (char*) encrypted->init_vector, IV_SIZE);
                            char decrypted_data[encrypted_data_size];
                            size_t size = decrypt_cipher((char*)encrypted -> data, encrypted_data_size, iv, decrypted_data, encrypt_mac);
                            write(1, decrypted_data, size); //check later
                        }
                        free(server_window[left_pointer]);
                        server_window[left_pointer] = NULL;
                        left_pointer += 1;
                        if (left_pointer < MAX_PACKET_SEND_SIZE - 20) {
                            right_pointer += 1;
                        }
                    }

                    // check whether there is data from input to send as well as ack
                    Packet* new_packet = read_from_stdin(flag, encrypt_mac, input_window, curr_packet_num, input_left, input_right, timer_active, timer_start);

                     // if not, send pure ack packet
                    if (new_packet == NULL) {

                        send_ACK(left_pointer, sockfd, clientaddr);
                       
                    }
                    // send data + ack
                    else {
                        new_packet->acknowledgment_number = htonl(left_pointer - 1);
                        input_window[curr_packet_num] = new_packet;
                        // fprintf(stderr, "SERVER sent packet #: %d\n", curr_packet_num);

                        // input_window[curr_packet_num] = (Packet*)malloc(sizeof(Packet) + ntohs(new_packet->payload_size));
                        // if (input_window[curr_packet_num] == NULL) {
                        //     perror("Memory allocation failed");
                        //     close(sockfd);
                        //     return 1;
                        // }
                        // memcpy(input_window[curr_packet_num], new_packet, sizeof(Packet) + ntohs(new_packet->payload_size));
                        // fprintf(stderr, "meow: %d\n", ntohs(new_packet->payload_size));
                        curr_packet_num += 1;

                        // send the packet
                        int did_send = sendto(sockfd, new_packet, sizeof(Packet) + ntohs(new_packet->payload_size), 0, (struct sockaddr *)&clientaddr, sizeof(clientaddr));
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
                // else{
                //     send_ACK(received_packet_number + 1, sockfd, clientaddr);
                // }
                else{
                    //fprintf(stderr, "revd pack num%d\n",received_packet_number );
                    // FROM RAWR: send ack is combined? with the next stdin read so don't need to send (commented out below)
                    // send_ACK(received_packet_number + 1, sockfd, clientaddr);
                    if(input_left == 1 && server_window[1] != NULL && input_window[1] == NULL){//can only make server hello if we recieve client hello and input window 0 is null
                        fprintf(stderr, "RECEIVE CLIENT HELLO\n");
                        Packet* client_hello_packet = server_window[1];

                        ClientHello *client_hello =  (ClientHello *) client_hello_packet -> data;
                        SecurityHeader* header = (SecurityHeader*) &client_hello -> header;
                        if (header->msg_type != CLIENT_HELLO) {
                            close(sockfd);

                            return 1;
                        }

                        uint8_t client_comm_type = client_hello->comm_type;
                        if(client_comm_type == 1){
                            encrypt_mac = true;
                        }
                        else{
                            encrypt_mac = false;
                        }
                        uint8_t* client_nonce = (uint8_t*)malloc(32);
                        memcpy(client_nonce, client_hello->client_nonce, 32);
                        // create & send server hello
                        Packet* server_hello = create_server_hello(client_comm_type, client_nonce, server_nonce_buf);
                        input_window[1] = server_hello;
                        // ServerHello* srvh = (ServerHello*) server_hello -> data; 

                        sendto(sockfd, server_hello, sizeof(Packet) + ntohs(server_hello -> payload_size), 0, (struct sockaddr *)&clientaddr, sizeof(clientaddr));
                        fprintf(stderr, "SENT SERVER HELLO\n");

                        curr_packet_num += 1;
                        free(server_window[1]);
                        server_window[1] = NULL;
                        // //fprintf(stderr, "Sleft pointer: %d\n", left_pointer);
                        left_pointer += 1;
                        input_left +=1 ;
                    }
                    else if(input_left == 2 && server_window[2] != NULL && input_window[2] == NULL){ //this means we have recieved 2nd ack + key exchange, need to parse it
                        fprintf(stderr, "RECEIVED KEY EXCHANGE\n");
                        Packet* key_exchange_packet = server_window[2];
                        KeyExchangeRequest* key_exchange = (KeyExchangeRequest*) key_exchange_packet -> data; // this starts at the security header

                        SecurityHeader* header = &key_exchange -> header;
                        if (header->msg_type != KEY_EXCHANGE_REQUEST) {
                            close(sockfd);
                            return 1;
                        }
                        // Extract certificate from key_exchange-> data
                        uint16_t client_cert_size = ntohs(key_exchange->cert_size);
                        uint8_t raw_cert_buf[client_cert_size];
                        memcpy(raw_cert_buf, key_exchange->data, client_cert_size);
                        Certificate* client_cert = (Certificate *) raw_cert_buf;
                            
                        // this is the signature of the server nonce
                        uint8_t sig_size = key_exchange->sig_size;
                        uint8_t client_sig[sig_size];
                        memcpy(client_sig, key_exchange -> data + client_cert_size, sig_size);
                        uint16_t key_len = ntohs(client_cert->key_len);
                        // int key_len = ntohs(client_cert->key_len);
                        uint8_t *client_public_key = client_cert->data;
                        load_peer_public_key((char*) client_cert->data, key_len);

                        uint8_t *signature = client_cert->data + key_len;
                        size_t signature_len = client_cert_size - sizeof(Certificate) - key_len;
                        // verify client certificate
                        // int verify(char* data, size_t size, char* signature, size_t sig_size, EVP_PKEY* authority)
                        if (verify((char*) client_public_key, key_len, (char*) signature, signature_len, ec_peer_public_key) != 1) {
                            fprintf(stderr, "Verification of client certificate failed.\n");
                            close(sockfd);
                            exit(EXIT_FAILURE);
                        }
                        
                        // Verify client nonce
                        if (verify((char*) server_nonce_buf, 32, (char*)client_sig, sig_size, ec_peer_public_key) != 1) {
                            fprintf(stderr, "Verification of client signature failed.\n");
                            close(sockfd);
                            exit(EXIT_FAILURE);
                        }

                        // derive shared secret
                        derive_secret();

                        // create & send fin message
                        Packet* server_fin = create_fin();
                        input_window[2] = server_fin;
                        int did_send = sendto(sockfd, server_fin, sizeof(Packet) + ntohs(server_fin -> payload_size) , 0, (struct sockaddr *)&clientaddr, clientsize);
                        if (did_send < 0) {
                            perror("Failed to send server fin msg");
                        }
                        fprintf(stderr, "SENT FIN\n");

                        curr_packet_num += 1;
                        free(server_window[2]);
                        server_window[2] = NULL;
                        left_pointer += 1;
                        input_left +=1;
                    }
                }
            }
        }

        // no bytes received, just send whatever is in standard input
        if (!handshake && client_send == true) {
            Packet* new_packet = read_from_stdin(flag, encrypt_mac, input_window, curr_packet_num, input_left, input_right, timer_active, timer_start);
            
            // send the packet
            if (new_packet != NULL) {
                // fprintf(stderr, "creating new packet\n");
                input_window[curr_packet_num] = new_packet;
                // fprintf(stderr, "SERV sent packet #: %d\n", curr_packet_num);

                // input_window[curr_packet_num] = (Packet*)malloc(sizeof(Packet) + ntohs(new_packet->payload_size));
                // if (input_window[curr_packet_num] == NULL) {
                //     perror("Memory allocation failed");
                //     close(sockfd);
                //     return 1;
                // }
                // memcpy(input_window[curr_packet_num], new_packet, sizeof(Packet) + ntohs(new_packet->payload_size));
                curr_packet_num += 1;
                int did_send = sendto(sockfd, new_packet, sizeof(Packet) + ntohs(new_packet->payload_size), 0, (struct sockaddr *)&clientaddr, sizeof(clientaddr));
                if (did_send < 0) return errno;
                
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
    // memset(read_buf, 0, BUF_SIZE);
    // fprintf(stderr, "reading from stdin\n");
    
   // check if we're within the send window
    int bytesRead = 0;
    if (curr_packet_num >= input_left && curr_packet_num <= input_right){
        if (flag == 1 && encrypt_mac) {
            bytesRead = read(STDIN_FILENO, read_buf, 898);
        } 
        else if (flag == 1 && !encrypt_mac) {
            bytesRead = read(STDIN_FILENO, read_buf, 930);
        } 
        else {
            bytesRead = read(STDIN_FILENO, read_buf, MAX_SEGMENT_SIZE);
        }
    }
    else {
        return NULL;
    }

    if (bytesRead > 0) {
        // fprintf(stderr, "bytes read from stdin %d\n", bytesRead);
        // fprintf(stderr, "current packet num %d\n", curr_packet_num);

        // create a new packet
        Packet* new_packet = (Packet*)malloc(sizeof(Packet) + 1024);
        new_packet->packet_number = htonl((uint32_t) curr_packet_num);
        new_packet->acknowledgment_number = htonl((uint32_t)0);

        // encrypt data 
        if (flag == 1) {
            //fprintf(stderr, "ENCRYPT DATA\n");
            // output_size = input_size + (block_size - (input_size % block_size))
            size_t block_size = EVP_CIPHER_block_size(EVP_aes_256_cbc());
            size_t cipher_buf_size = bytesRead + (block_size - (bytesRead % block_size));
            // fprintf(stderr, "cipher buf size: %ld \n", cipher_buf_size);
            char *cipher = (char *)malloc(cipher_buf_size);
            char iv[IV_SIZE];
            
            // BUGGY -- SEGFAULT / INVALID POINTER ERROR HAPPENS HERE
            size_t cipher_size = encrypt_data(read_buf, bytesRead, iv, cipher, int(encrypt_mac));
            //fprintf(stderr, "cipher size: %ld \n", cipher_size);

            // BUGGY -- DOUBLE FREE / INVALID POINTER HAPPENS SOMEWHERE HERE

            // create encrypted data message
            // no mac 
            if (!encrypt_mac) {
                EncryptedData* encrypt_data = (EncryptedData*)malloc(sizeof(EncryptedData) + cipher_size);
                encrypt_data->payload_size = htons(cipher_size);
                encrypt_data->padding = 0;
                memcpy(encrypt_data->init_vector, iv, IV_SIZE);
                memcpy(encrypt_data->data, cipher, cipher_size);

                encrypt_data -> header.msg_type = DATA; 
                encrypt_data -> header.padding = 0; 
                encrypt_data -> header.msg_len = htons(sizeof(EncryptedData) + cipher_size + MAC_SIZE - sizeof(SecurityHeader));

                // populate udp packet
                new_packet->payload_size = htons(sizeof(EncryptedData) + cipher_size);
                memcpy(new_packet->data, encrypt_data, sizeof(EncryptedData) + cipher_size);
                // free(cipher);
                // free(encrypt_data);
            }
            // mac (so hungry i need a big mac rn)
            // this is causing me to lose braincells.
            else {
                EncryptedData* encrypt_data = (EncryptedData*)malloc(sizeof(EncryptedData) + cipher_size + MAC_SIZE);
                encrypt_data->payload_size = htons(cipher_size);
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
                encrypt_data -> header.msg_len = htons(sizeof(EncryptedData) + cipher_size + MAC_SIZE - sizeof(SecurityHeader)); 

                // populate udp packet
                new_packet->payload_size = htons(sizeof(EncryptedData) + cipher_size + MAC_SIZE);
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

// send fin message to client
Packet *create_fin() {
    Finished* server_fin = (Finished*)malloc(sizeof(Finished));
    server_fin -> header.msg_type = FINISHED; 
    server_fin -> header.padding = 0; 
    server_fin -> header.msg_len = htons(sizeof(Finished) - sizeof(SecurityHeader)); 
    Packet* packet = (Packet*)malloc(sizeof(Packet) + sizeof(Finished));
    if (!packet) {
        perror("Failed to allocate memory for packet");
        free(server_fin);
        exit(EXIT_FAILURE);
    }

    // Fill in the packet fields
    packet->packet_number = htonl(2); 
    packet -> acknowledgment_number = htonl(3);
    packet->payload_size = htons(sizeof(Finished));
    // packet->padding = 0;
    memcpy(packet->data, server_fin, sizeof(Finished));

    //fprintf(stderr, "size of fin packet: %d\n", packet->payload_size);

    // Free the temporary Finished message memory
    free(server_fin);
    server_fin = NULL;
    return packet;
}

// send ServerHello message back to client
Packet *create_server_hello(int comm_type, uint8_t *client_nonce, uint8_t *server_nonce_buf) {
    uint8_t sig_size = sign((char*)client_nonce, 32, 0);
    if (sig_size == 0) {
        fprintf(stderr, "Invalid signature size\n");
        return nullptr;
    }

    ServerHello* server_hello = (ServerHello*)malloc(sizeof(ServerHello) + cert_size + sig_size);
    if (server_hello == nullptr) {
        fprintf(stderr, "Memory allocation failed for ServerHello.\n");
        return nullptr;
    }

    server_hello->header.msg_type = SERVER_HELLO; 
    server_hello->header.padding = 0; 
    server_hello->comm_type = comm_type;
    // fprintf(stderr, "c type %d\n", comm_type);
    // Generate server nonce
    memset(server_nonce_buf, 0, 32);
    generate_nonce((char*)server_nonce_buf, 32);
    memcpy(server_hello->server_nonce, server_nonce_buf, 32);
    
    // Copy certificate
    memcpy(server_hello->data, certificate, cert_size);
    server_hello->cert_size = htons(cert_size);

    // Debug: Print server nonce
    // fprintf(stderr, "Server nonce: ");


    // Allocate memory for signature and copy it
    char *server_nonce_sig = (char*)malloc(sig_size);
    if (!server_nonce_sig) {
        fprintf(stderr, "Memory allocation failed for signature.\n");
        free(server_hello);
        return nullptr;
    }
    uint8_t ss = sign((char*)client_nonce, 32, server_nonce_sig);
    memcpy(server_hello->data + cert_size, server_nonce_sig, ss);
    free(server_nonce_sig);

    server_hello->sig_size = ss;
    server_hello->header.msg_len = htons(sizeof(ServerHello) + cert_size + ss - sizeof(SecurityHeader));

    size_t server_hello_size = sizeof(ServerHello) + cert_size + ss;
    Packet* packet = (Packet*)malloc(sizeof(Packet) + server_hello_size);
    if (!packet) {
        perror("Failed to allocate memory for packet");
        free(server_hello);
        return nullptr;
    }

    packet->packet_number = htonl(1);
    packet->acknowledgment_number = htonl(1);
    memset(packet->padding, 0, sizeof(packet->padding));
    packet->payload_size = htons(server_hello_size);

    memcpy(packet->data, server_hello, server_hello_size);
    free(server_hello);
    return packet;
}


// Sends cumulative ACK depending on the packet number received
void send_ACK(uint32_t left_window_index, int sockfd, struct sockaddr_in clientaddr) {
    Packet ack_packet = {0};
    ack_packet.acknowledgment_number = htonl(left_window_index -1 );
    sendto(sockfd, &ack_packet, sizeof(Packet), 0, (struct sockaddr *)&clientaddr, sizeof(clientaddr));
}