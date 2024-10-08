#include <iostream>
#include <sys/socket.h> // Socket interface
#include <sys/time.h>
#include <arpa/inet.h>  // Internet protocol
#include <string.h>     // strlen
#include <unistd.h>     // close, etc.
#include <errno.h>      // Get errorno
#include <stdio.h>
#include <fcntl.h>
#include <openssl/err.h>
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
Packet *create_client_hello(char* client_nonce_buf, bool encrypt_mac);
Packet *create_key_exchange(char* client_nonce_buf, ServerHello* server_hello, int sockfd, struct sockaddr_in serveraddr);
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
    int flags2 = fcntl(STDIN_FILENO, F_GETFL);
    flags2 |= O_NONBLOCK;
    fcntl(STDIN_FILENO, F_SETFL, flags2);

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
    int input_right = 20;
    // initialize timer
    bool timer_active = false;
   
    char* client_nonce_buf = (char*) malloc(32);

    struct timeval timer_start;

    // security stuff
    bool handshake = false;
    bool encrypt_mac = false;
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
                    fprintf(stderr, "Retransmitting packet with num: %d\n", input_left);
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
                input_window[curr_packet_num] = create_client_hello(client_nonce_buf, encrypt_mac); //create client hello if not yet created
                sendto(sockfd, input_window[curr_packet_num], sizeof(ClientHello) + 12, 0, (struct sockaddr *)&serveraddr, serversize); //send packet
                curr_packet_num += 1;
                fprintf(stderr, "SENT CLIENT HELLO\n");
            }
            
        }

        // listen to socket for incoming packets from server
        char server_buf[BUF_SIZE + 12];
        int bytes_recvd = recvfrom(sockfd, server_buf, BUF_SIZE + 12, 0, (struct sockaddr*)&serveraddr, &serversize);
        
        if (bytes_recvd > 0) {
            //printf("incoming packet from server\n");
            Packet* received_packet = (Packet*)server_buf;
            uint32_t received_packet_number = ntohl(received_packet->packet_number);
            uint32_t received_ack_number = ntohl(received_packet->acknowledgment_number);
            uint16_t received_payload_size = ntohs(received_packet->payload_size);
            
            // fprintf(stderr, "received ack #: %d\n", received_ack_number);
            // fprintf(stderr, "received packet #: %d\n", received_packet_number);
            // fprintf(stderr, "received payload size: %d\n", received_payload_size);

            // receive an ack --> update input window
            if (received_ack_number != 0 || input_left ==1) {
                // if(received_ack_number == 3 && handshake){
                //     handshake = false;
                // }
                if (received_ack_number >= input_left) {
                    // free packets from input_left to ack #
                    for (int i = input_left; i <= received_ack_number; i++) {
                        if (input_window[i] != NULL) {
                            //fprintf(stderr, "HAHAHA\n");
                            free(input_window[i]);
                            
                            input_window[i] = NULL;
                        }
                    }
                    //fprintf(stderr, "HAHAHA2\n");
                    input_left = received_ack_number + 1 ;
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
                        // write all data in buffer (regardless of flag bc buffer contents should be unecrypted alr)
                        // write packet is leftmost packet in buffer
                        Packet *current_write_packet = (Packet*) server_window[left_pointer];
                        uint8_t* current_write_packet_data = current_write_packet -> data; 
                        // fprintf(stdout, "LK:JLK:DSFJSDF%d\n", left_pointer);
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

                        send_ACK(left_pointer, sockfd, serveraddr);
                       
                    }
                    // send data + ack
                    else {
                        new_packet->acknowledgment_number = htonl(left_pointer - 1);
                        input_window[curr_packet_num] = new_packet;

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
                        int did_send = sendto(sockfd, new_packet, sizeof(Packet) + ntohs(new_packet->payload_size), 0, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
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
                // doing security handshake 
                else {
                    if(curr_packet_num == 2 && server_window[1] != NULL && input_window[2] == NULL){ //create the exchange message if recieved an serverhello/ack from server, server send the hello, and input window null
                        fprintf(stderr, "RECEIVED SERVER HELLO\n");
                        Packet* server_hello_packet = server_window[1];
                        ServerHello *server_hello = (ServerHello *) server_hello_packet -> data;
                        SecurityHeader* header = &server_hello -> header;
                        if (header->msg_type != SERVER_HELLO) {
                            fprintf(stderr, "expected server hello but didn't receive it\n");
                            close(sockfd);
                            return 1;
                        }

                        // Close the file for server public key
                        Packet *key_exchange_packet = create_key_exchange(
                            client_nonce_buf,
                            server_hello,
                            sockfd, 
                            serveraddr
                        );
                        // fprintf(stderr, "here6\n");
                        input_window[curr_packet_num] = key_exchange_packet;
                        // Calculate the total size of the packet to send
                        size_t packet_size = sizeof(Packet) + ntohs(key_exchange_packet->payload_size);
                        // Send the packet
                        int did_send = sendto(sockfd, key_exchange_packet, packet_size, 0, (struct sockaddr *)&serveraddr, serversize);
                        if (did_send < 0) {
                            fprintf(stderr, "here\n");
                            return errno;
                        }
                        fprintf(stderr, "here7\n");

                        // free(client_nonce_signed);

                        curr_packet_num += 1;
                        free(server_window[1]);
                        server_window[1] = NULL;
                        left_pointer += 1;
                        input_left +=1;
                        fprintf(stderr, "SENT KEY EXCHANGE\n");
                    }
                    else if (curr_packet_num == 3) {
                        Packet* finished_packet = server_window[2];
                        Finished* finished = (Finished*) finished_packet -> data;

                        SecurityHeader* header = &finished -> header;
                        if (header->msg_type != FINISHED) {
                            close(sockfd);
                            return 1;
                        }

                        fprintf(stderr, "RECEIVED FIN \n");
                        handshake = false;
                        send_ACK(3, sockfd, serveraddr);
                        if (encrypt_mac) {
                            derive_keys();

                            //fprintf(stderr, "Encryption key: %.*s\n", SECRET_SIZE, enc_key);
                            //fprintf(stderr, "Authentication key: %.*s\n", SECRET_SIZE, mac_key);
                        }
                        free(server_window[2]);
                        server_window[2] = NULL;
                        left_pointer += 1;
                        fprintf(stderr, "MAKE %d %d\n", left_pointer, input_left);
                    }
                }
            }
        }

        // no packets received, just send whatever is in standard input
        if (!handshake) {
            Packet* new_packet = read_from_stdin(flag, encrypt_mac, input_window, curr_packet_num, input_left, input_right, timer_active, timer_start);
            
            // send the packet
            if (new_packet != NULL) {
                input_window[curr_packet_num] = new_packet;
                // input_window[curr_packet_num] = (Packet*)malloc(sizeof(Packet) + ntohs(new_packet->payload_size));
                // if (input_window[curr_packet_num] == NULL) {
                //     perror("Memory allocation failed");
                //     close(sockfd);
                //     return 1;
                // }
                // memcpy(input_window[curr_packet_num], new_packet, sizeof(Packet) + ntohs(new_packet->payload_size));
                curr_packet_num += 1;
                int did_send = sendto(sockfd, new_packet, sizeof(Packet) + ntohs(new_packet->payload_size), 0, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
                if (did_send < 0) return errno;
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

    // check if we're within the send window
    int bytesRead = 0;
    // fprintf(stderr, "curr_packet_num: %d, input_left: %d, input_right: %d\n", curr_packet_num, input_left, input_right);
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
        // fprintf(stderr, "current packet num %d\n", curr_packet_num);

        // create a new packet
        Packet* new_packet = (Packet*)malloc(sizeof(Packet) + 1024);
        new_packet->packet_number = htonl((uint32_t) curr_packet_num);
        new_packet->acknowledgment_number = htonl((uint32_t)0);

        // encrypt data 
        if (flag == 1) {
            // output_size = input_size + (block_size - (input_size % block_size))

            size_t block_size = EVP_CIPHER_block_size(EVP_aes_256_cbc());
            size_t cipher_buf_size = bytesRead + (block_size - (bytesRead % block_size));
            char *cipher = (char *)malloc(cipher_buf_size);
            char iv[IV_SIZE];
            
            // BUGGY -- SEGFAULT / INVALID POINTER ERROR HAPPENS HERE
            size_t cipher_size = encrypt_data(read_buf, bytesRead, iv, cipher, int(encrypt_mac));

            //fprintf(stderr, "cipher size: %ld \n", cipher_size);

            // BUGGY -- DOUBLE FREE / INVALID POINTER HAPPENS SOMEWHERE HERE

            // create encrypted data message
            // no mac 
            if (!encrypt_mac) {
                // fprintf(stderr, "ECYPRT MAC MODE\n");
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
                // fprintf(stderr, "NOT ECYPRT MAC MODE\n");
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
                // fprintf(stderr, "HMAC over data: %.*s\n", MAC_SIZE, mac);
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
            fprintf(stderr, "BYTES READ %d\n", ((uint16_t)bytesRead));
            memcpy(new_packet->data, read_buf, bytesRead);
        }

        // free(read_buf);

        return new_packet;
    }
    // free(read_buf);
    return NULL;
}



// Sends cumulative ACK depending on the packet number received
void send_ACK(uint32_t left_window_index, int sockfd, struct sockaddr_in serveraddr) {
    Packet ack_packet = {0};
    ack_packet.acknowledgment_number = htonl(left_window_index -1);
    sendto(sockfd, &ack_packet, sizeof(Packet), 0, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
}

Packet *create_client_hello(char* client_nonce_buf, bool encrypt_mac){
    ClientHello* client_hello = (ClientHello*)malloc(sizeof(ClientHello));
    if (client_hello == nullptr) {
        //fprintf(stderr, "Memory allocation failed for ClientHello.\n");
        return nullptr;
    }
    // Initialize comm_type based on flag
    client_hello->comm_type = int(encrypt_mac); 
    // Initialize padding to zero
    // memset(client_hello->padding, 0, 2);
    // Generate client nonce
    // char client_nonce_buf[32]; // 32 bytes for the nonce
    generate_nonce(client_nonce_buf, 32); // fill nonce_buf with 32 bytes of data
    memcpy(client_hello->client_nonce, client_nonce_buf, 32);
    client_hello -> header.msg_type = CLIENT_HELLO; 
    client_hello -> header.padding = 0; 
    client_hello -> header.msg_len = htons(sizeof(ClientHello) - sizeof(SecurityHeader)); 
    //fprintf(stderr, "ch size %ld\n", sizeof(client_hello) - sizeof(SecurityHeader));
    Packet *packet = (Packet *)malloc(sizeof(Packet) + sizeof(ClientHello));
    if (packet == nullptr) {
        //fprintf(stderr, "Memory allocation failed for Packet.\n");
        free(client_hello);
        return nullptr;
    }
    memcpy(packet->data, client_hello, sizeof(ClientHello));

    packet->packet_number = htonl(1);
    packet->acknowledgment_number = htonl(0);
    packet->payload_size = htons(sizeof(ClientHello)); //flag for later
    fprintf(stderr, "size%ld\n", sizeof(ClientHello));
    free(client_hello); // Free the memory allocated for ClientHello since it's copied into packet
    return packet;
}

Packet *create_key_exchange(char* client_nonce_buf, ServerHello* server_hello, int sockfd, struct sockaddr_in serveraddr) {
    // extract server comm type
    unsigned char *ptr = (unsigned char *)server_hello;

    uint8_t server_comm_type = server_hello->comm_type;
    // size of signature over client nonce
    uint8_t server_sig_size = server_hello->sig_size; 

    // extract server nonce
    uint8_t server_nonce[32];
    memcpy(server_nonce, server_hello->server_nonce, 32);
    
    // extract server certificate
    uint16_t server_cert_size = ntohs(server_hello->cert_size);

    uint8_t raw_cert_buf[server_cert_size];
    memcpy(raw_cert_buf, server_hello->data, server_cert_size);

    // cast to a Certificate pointer for easier parsing
    Certificate* server_cert = (Certificate*) raw_cert_buf;
    uint16_t key_len = ntohs(server_cert->key_len);
    // for (int i = 0; i < 284 ; i++) {
    //     fprintf(stdout, "%02x ", (unsigned char)ptr[i]);
    // }
    // fprintf(stderr, "\n");
    // get server public key from certificate
    char* server_public_key = (char*)malloc(key_len);
    memcpy(server_public_key, server_cert->data, key_len);
    if(memcmp(server_public_key, raw_cert_buf + 4, key_len)!= 0){
        fprintf(stderr, "DI\n");
    }

    // get signature from certificate
    uint8_t *signature = server_cert -> data + key_len;
    size_t signature_len = server_cert_size - key_len - sizeof(Certificate);


    // extract signature of client nonce
    char* client_nonce_signed = (char*) malloc(server_sig_size);
    memcpy(client_nonce_signed, server_hello->data + server_cert_size , server_sig_size);
    if(memcmp(client_nonce_signed, ptr +40 + 166, server_sig_size)!= 0){
        fprintf(stderr, "DI\n");
    }
    // Verify server signature inside of the certificate
    if (verify(server_public_key, key_len, (char*) signature, signature_len, ec_ca_public_key) !=1) {
        fprintf(stderr, "Verification of server certificate failed.\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // load server public key
    load_peer_public_key(server_public_key, key_len);
    for (int i = 0; i < key_len; ++i) {
        fprintf(stderr, "%02X ", (unsigned char)server_public_key[i]);
    }
    if(ec_peer_public_key == NULL){
        fprintf(stderr, "errrrrm what the sigma\n");
    }

    // verify server signature over client nonce
    if (verify((char*)client_nonce_buf, 32, (char*)server_hello->data + server_cert_size, server_sig_size, ec_peer_public_key) !=1) {
        fprintf(stderr, "Verification of nonce signature failed.\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    generate_private_key(); //now private key is stored in private key var 
    derive_public_key(); //now public key is stored in variable "public_key"
    derive_secret();  //now secret variable has the private key
    
    //now we need to create a certificate and sign the certificate with our own private key
    size_t self_signature_size = sign((char*)public_key, key_len, NULL);
    // Allocate memory for client certificate
    Certificate* client_cert = (Certificate*)malloc(sizeof(Certificate) + pub_key_size + self_signature_size);
    // Initialize client_cert
    client_cert -> key_len = htons(pub_key_size); 
    client_cert -> padding = ntohs(0);
    memcpy(client_cert->data, public_key, pub_key_size); 

    size_t self_sig_size = sign((char*)public_key, sizeof(public_key), NULL);
    char *self_signature = (char*)malloc(self_sig_size);
    size_t ss = sign((char*)public_key, pub_key_size, self_signature);
    memcpy(client_cert->data + pub_key_size, self_signature, ss);
    free(self_signature); 

    //now we have to sign the server nonce
    size_t nonce_signature_size = sign((char*)server_nonce, sizeof(server_nonce), NULL);
    char *nonce_signature = (char*)malloc(nonce_signature_size);
    size_t ns = sign((char*)server_nonce, 32, nonce_signature);

    if (nonce_signature == NULL) {
        //fprintf(stderr, "Failed to sign the server nonce.\n");
        free(nonce_signature);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    //now create the keyexchage packet
    size_t total_size = sizeof(KeyExchangeRequest) + sizeof(Certificate) + pub_key_size + ss + ns;
    KeyExchangeRequest* key_exchange = (KeyExchangeRequest*) malloc(total_size);
    key_exchange -> sig_size = ns; 
    key_exchange -> cert_size = htons(sizeof(Certificate) + ss + pub_key_size);
    // copy certificate into data
    memcpy(key_exchange->data, client_cert, sizeof(Certificate) + pub_key_size + ss); 
    // copy signature of server nonce into data
    memcpy(key_exchange->data + sizeof(Certificate) + ss + pub_key_size , nonce_signature,  ns); 
    
    key_exchange -> header.msg_type = KEY_EXCHANGE_REQUEST; 
    key_exchange -> header.padding = htons(0); 
    key_exchange -> header.msg_len = htons(total_size - sizeof(KEY_EXCHANGE_REQUEST));//may be wrong
    
    Packet *packet = (Packet *)malloc(sizeof(Packet) + ntohs(key_exchange->header.msg_len));
    if (packet == nullptr) {
        //fprintf(stderr, "Memory allocation failed for Packet.\n");
        free(key_exchange);
        return nullptr;
    }
    memcpy(packet->data, key_exchange, total_size);
    packet->packet_number = htonl(2); // You may need to set this accordingly
    packet->acknowledgment_number = htonl(2); // You may need to set this accordingly
    packet->payload_size = htons(total_size);

    free(nonce_signature);
    free(key_exchange);
    return packet; 
}
