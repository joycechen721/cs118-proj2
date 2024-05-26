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

// helper functions
int checkFiles(int flag, FILE *file);
void send_ACK(uint32_t left_window_index, int sockfd, struct sockaddr_in client_addr);

// global variables
#define CONGESTION_WINDOW_SIZE 20 // at any point there should be max 20 unacked packets
#define MAX_SEGMENT_SIZE 10 // payload size for each packet (bytes)
#define MAX_PACKET_SEND_SIZE 2001
#define RTO 1 // retransmission timer

int main(int argc, char *argv[]) {
    // Parse the arguments
    int flag = atoi(argv[1]);
    char *hostname = argv[2];
    int port = atoi(argv[3]);
    char *ca_public_key_file = NULL;
    if (flag == 1){
        ca_public_key_file = argv[4];
    }
    // check files
    FILE *public_key = fopen(ca_public_key_file, "r");
    int result = checkFiles(flag, public_key);
    if (!result) {
        fprintf(stderr, "Flag not set or files not found. Exiting.\n");
        return 1;
    }

    /* 1. Create socket */
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    // Setup fd/stdin set for nonblock
    int flags = fcntl(sockfd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(sockfd, F_SETFL, flags);
    fcntl(STDIN_FILENO, F_SETFL, flags);

    /* 2. Construct server address */
    struct sockaddr_in serveraddr;
    serveraddr.sin_family = AF_INET; // use IPv4
    serveraddr.sin_addr.s_addr = INADDR_ANY;

    // Set sending port
    serveraddr.sin_port = htons(port); // Big endian
    int BUF_SIZE = 1024;
    char client_buf[BUF_SIZE];
    struct sockaddr_in clientaddr; // Same information, but about client
    socklen_t clientsize = sizeof(clientaddr);

    int curr_packet_num = 1;
    int left_pointer = 1; 
    int right_pointer = 20;

    Packet* server_window[MAX_PACKET_SEND_SIZE]; // server window, initialize all values to NULL 
    for (int i = 0; i < MAX_PACKET_SEND_SIZE; i++) {
        server_window[i] = NULL;
    }
    
    int input_left = 1; // oldest unacked packet (leftmost)
    int input_right = 19;

    Packet* input_window[MAX_PACKET_SEND_SIZE]; // input window, initialize all values to NULL 
    for (int i = 0; i < MAX_PACKET_SEND_SIZE; i++) {
        input_window[i] = NULL;
    }

    time_t start = time(0); // initialize timer
    while(true){
        // read from stdin & send data to server
        char read_buf[BUF_SIZE];
        memset(read_buf, 0, BUF_SIZE);
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

            // buffer to receive data from server
            int BUF_SIZE = 1024;
            char server_buf[BUF_SIZE];
            socklen_t serversize;
            int bytes_recvd = recvfrom(sockfd, server_buf, BUF_SIZE, 0, (struct sockaddr*)&serveraddr, &serversize);
            
            if (bytes_recvd > 0) {
                Packet* received_packet = (Packet*)server_buf;
                uint32_t client_packet_number = ntohl(received_packet->packet_number);
                uint32_t client_ack_number = ntohl(received_packet->acknowledgment_number);
                uint16_t client_payload_size = ntohs(received_packet->payload_size);
                printf("received ack: %d\n", client_ack_number);
                
                // Not an ack
                if (client_packet_number != 0) {
                    // Update window to reflect new packet
                    server_window[client_packet_number] = (Packet*)malloc(sizeof(Packet) + client_payload_size);
                    if (server_window[client_packet_number] == NULL) {
                        perror("Memory allocation failed");
                        close(sockfd);
                        return 1;
                    }
                    memcpy(server_window[client_packet_number], received_packet, sizeof(Packet) + client_payload_size);

                    // Update left pointer until it points to nothing, adjust right pointer too
                    while (server_window[left_pointer] != NULL) { //move sender window forward since client acked
                        uint8_t *payload = received_packet->data;
                        write(1, payload, client_payload_size);
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
                // An ack
                else {
                    if (client_ack_number > input_left) {
                        start = time(0);
                        // Free packets from input_left to ack #
                        for (int i = input_left; i < client_ack_number; i++) {
                            if (input_window[i] != NULL) {
                                free(input_window[i]);
                                input_window[i] = NULL;
                            }
                        }
                        input_left = client_ack_number;
                        input_right = 20 + input_left;
                    }
                }
            }
        }
        // TEST CODE for SEND:
        // // char client_buf[] = "Hello earth!";
        // int did_send = sendto(sockfd, client_buf, strlen(client_buf), 0, (struct sockaddr*) &serveraddr, sizeof(serveraddr));
        // if (did_send < 0) continue;

        /* 4. Create buffer to store incoming data */
        // write(1, server_buf, bytes_recvd);
    }
    /* 6. You're done! Terminate the connection */     
    close(sockfd);
    return 0;
}

int checkFiles(int flag, FILE *file) {
    if (flag == 1) {
        if (file == NULL) {
            fprintf(stderr, "File could not be opened.\n");
            if (file != NULL) {
                fclose(file);
            }
            return 0; // File is not valid
        }
        return 1;
    }
    return 1;
}

// Sends cumulative ACK depending on the packet number received
void send_ACK(uint32_t left_window_index, int sockfd, struct sockaddr_in client_addr) {
    Packet ack_packet = {0};
    ack_packet.acknowledgment_number = htonl(left_window_index);
    sendto(sockfd, &ack_packet, sizeof(ack_packet), 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
}