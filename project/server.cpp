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
int checkFiles(int flag, FILE *pkey, FILE *cert);
void send_ACK(uint32_t left_window_index, int sockfd, struct sockaddr_in client_addr, socklen_t clientsize);

// global variables
#define CONGESTION_WINDOW_SIZE 20 // at any point there should be max 20 unacked packets
#define MAX_SEGMENT_SIZE 10 // payload size for each packet (bytes)
#define MAX_PACKET_SEND_SIZE 2001
#define RTO 1 // retransmission timer

int main(int argc, char *argv[]) {
    // Parse the arguments
    int flag = atoi(argv[1]);
    int port = atoi(argv[2]);
    char *private_key_file = NULL;
    char *certificate_file = NULL;
    if (flag == 1){
        private_key_file = argv[3];
        certificate_file = argv[4];
    }
    // check files
    FILE *pkey = fopen(private_key_file, "r");
    FILE *cert = fopen(certificate_file, "r");
    int result = checkFiles(flag, pkey, cert);
    if (!result){
        fprintf(stderr, "Flag not set or files not found. Exiting.\n");
        return 1;
    }
        
    /* 1. Create socket */
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    // Setup fd set for nonblock
    int flags = fcntl(sockfd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(sockfd, F_SETFL, flags);
    fcntl(STDIN_FILENO, F_SETFL, flags);

    /* 2. Construct our address */
    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET; // use IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY;

    // Set receiving port
    servaddr.sin_port = htons(port); // Big endian

    /* 3. Let operating system know about our config */
    int did_bind = bind(sockfd, (struct sockaddr*) &servaddr, 
                        sizeof(servaddr));
    // Error if did_bind < 0 :(
    if (did_bind < 0) return errno;

    /* 4. Create buffer to store incoming data */
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
    while (true) {
        char *client_ip = inet_ntoa(clientaddr.sin_addr);
        int client_port = ntohs(clientaddr.sin_port);
        /* Do some processing here */
        /* 5. Listen for data from clients */
        memset(client_buf, 0, BUF_SIZE);
        int bytes_recvd = recvfrom(sockfd, client_buf, BUF_SIZE, 0, (struct sockaddr*) &clientaddr, &clientsize);
        // if (bytes_recvd <= 0) continue;
        if (bytes_recvd > 0) {
            // std::cout << "Received " << bytes_recvd << " bytes from " << client_ip << ":" << client_port << std::endl;

            Packet* received_packet = (Packet*)client_buf;
            uint32_t client_packet_number = ntohl(received_packet->packet_number);
            uint32_t client_ack_number = ntohl(received_packet->acknowledgment_number);
            uint16_t client_payload_size = ntohs(received_packet->payload_size);
            
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
                while (server_window[left_pointer] != NULL) {
                    uint8_t *payload = received_packet->data;
                    write(1, payload, client_payload_size);
                    left_pointer += 1;
                    if (left_pointer < MAX_PACKET_SEND_SIZE - 20) {
                        right_pointer += 1;
                    }
                }
                // Now we can send the cumulative ack
                send_ACK(left_pointer, sockfd, clientaddr, clientsize);
            } else {
                // An ack
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
        // TEST CODE FOR SENDS
        // // send data to client
        // char server_buf[] = "Hello world!";
        // int did_send = sendto(sockfd, server_buf, strlen(server_buf), 0, (struct sockaddr*) &clientaddr, sizeof(clientaddr));
        // if (did_send < 0)  continue;
        
        // Execution will stop here until `BUF_SIZE` is read or termination/error
        // Error if bytes_recvd < 0 :(
    // No data yet, we can continue processing at the top of this loop
        /* 6. Inspect data from client */
        // Print out data

        /* 7. Send data back to client */
    /* Data available; we can now process the data */                  
    }
    /* 8. You're done! Terminate the connection */     
    close(sockfd);
    return 0;
}


int checkFiles(int flag, FILE *pkey, FILE *cert) {
    if (flag == 1) {
        if (pkey == NULL || cert == NULL) {
            fprintf(stderr, "One or more files (private key or certificate file) could not be opened.\n");
            if (pkey != NULL) {
                fclose(pkey);
            }
            if (cert != NULL) {
                fclose(cert);
            }
            return 0; // File is not valid
        }
        return 1;
    }
    return 1;
}

// Sends cumulative ACK depending on the packet number received
void send_ACK(uint32_t left_window_index, int sockfd, struct sockaddr_in client_addr, socklen_t clientsize) {
    Packet ack_packet = {0};
    ack_packet.acknowledgment_number = htonl(left_window_index);
    sendto(sockfd, &ack_packet, sizeof(ack_packet), 0, (struct sockaddr *)&client_addr, clientsize);
}