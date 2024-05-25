#include <iostream>
#include <sys/socket.h> // Socket interface
#include <sys/time.h>
#include <arpa/inet.h>  // Internet protocol
#include <string.h>     // strlen
#include <unistd.h>     // close, etc.
#include <errno.h>      // Get errorno
#include <stdio.h>
#include <fcntl.h>
// ./server server <flag> <port> <private_key_file> <certificate_file>=

// helper functions
int checkFiles(int flag, FILE *pkey, FILE *cert);

//global variables
#define CONGESTION_WINDOW_SIZE 20 //at any point there should be max 20 unacked packets
#define MAX_SEGMENT_SIZE 1024 //payload size for each packet (bytes)
#define MAX_PACKET_SEND_SIZE 2001
#define RTO 1 //retransmission timer

typedef struct {
    uint32_t packet_number;        // 32-bit Packet Number
    uint32_t acknowledgment_number; // 32-bit Acknowledgment Number
    uint16_t payload_size;         // 16-bit Payload Size
    uint8_t padding[2];              // 16-bit Padding
    uint8_t data[0];     
} Packet;

int main(int argc, char *argv[])
{
    std::cout << "This is the server implementation!" << std::endl;
    // Parse the arguments
    int flag = atoi(argv[1]);
    int port = atoi(argv[2]);
    char *private_key_file = NULL;
    char *certificate_file = NULL;
    if (flag == 1)
    {
        private_key_file = argv[3];
        certificate_file = argv[4];
    }
    // check files
    FILE *pkey = fopen(private_key_file, "r");
    FILE *cert = fopen(certificate_file, "r");
    int result = checkFiles(flag, pkey, cert);

    if (!result)
    {
        fprintf(stderr, "Flag not set or files not found. Exiting.\n");
        return 1;
    }

    /* 1. Create socket */
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    /* 2. Construct our address */
    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    // Set receiving port
    int PORT = 8080;
    servaddr.sin_port = htons(PORT); // Big endian

    /* 3. Let operating system know about our config */
    if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
        return errno;

    // Setup fd set for nonblock
    int flags = fcntl(sockfd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(sockfd, F_SETFL, flags);

    /* 4. Create buffer to store incoming data */
    int BUF_SIZE = 1024;
    char client_buf[BUF_SIZE];
    struct sockaddr_in clientaddr; // Same information, but about client
    socklen_t clientsize = sizeof(clientaddr);

    int curr_packet_num = 1;
    int curr_ack = 0; //oldest unacked packet (leftmost)
    Packet* server_window[MAX_PACKET_SEND_SIZE]; //server window, initialize all values to -1 
    for (int i = 0; i < MAX_PACKET_SEND_SIZE; i++) {
        server_window[i] = NULL;
    }
    time_t start = time(0); //initialize timer
    
    while (true)
    {
        double seconds_since_start = difftime(time(0), start);
        if (seconds_since_start >= 1.0) {
            //resend leftmost packet
            
            start = time(0);
        }

        /* get client data from socket */
        int bytes_recvd = recvfrom(sockfd, client_buf, BUF_SIZE, 0, (struct sockaddr *)&clientaddr, &clientsize);
        Packet* received_packet = (Packet*)client_buf;

        uint32_t client_packet_number = ntohl(received_packet->packet_number);
        uint32_t client_ack_number = ntohl(received_packet->acknowledgment_number);
        uint16_t client_payload_size = ntohs(received_packet->payload_size);
        // Padding bytes are skipped
        uint8_t* client_payload = received_packet->data;
        //not an ack
        if (client_packet_number != 0) {
            //update window to reflect new packet
            server_window[client_packet_number] = received_packet; 
            //update left pointer until it points to nothing, adjust right pointer too
            while()
            //send an ack to client
        } 
        // an ack
        else {
            //new ack
            if (client_ack_number > curr_ack) {
                start = time(0);
            }
            //old ack
        }
        // No data yet, we can continue processing at the top of this loop
        // if (bytes_recvd <= 0) continue;
        
         /* Data available. Write to standard output*/
        printf("%s\n", bytes_recvd);
        
         /* Read from standard input & send to client */
        char *client_ip = inet_ntoa(clientaddr.sin_addr);
        int client_port = ntohs(clientaddr.sin_port);
        char server_buf[1024];
        read(STDIN_FILENO, server_buf, 1024);
        int did_send = sendto(sockfd, server_buf, strlen(server_buf), 0, (struct sockaddr *)&clientaddr, sizeof(clientaddr));
    }

    /* 8. You're done! Terminate the connection */
    close(sockfd);

    // include security stuff
    fclose(pkey);
    fclose(cert);

    return 0;
}


int checkFiles(int flag, FILE *pkey, FILE *cert)
{
    if (flag == 1)
    {
        if (pkey == NULL || cert == NULL)
        {
            fprintf(stderr, "One or more files (private key or certificate file) could not be opened.\n");

            // Close the file that was successfully opened (if any)
            if (pkey != NULL)
            {
                fclose(pkey);
            }
            if (cert != NULL)
            {
                fclose(cert);
            }

            return 0; // File is not valid
        }
        else
        {
            // If both files are successfully opened
            return 1; // Both files are valid
        }
    }
    return 1; // Default return if flag is not 1
}

// Sends cumulative ACK depending on the packet number received
// If the 
int send_ACK(Packet *packet, Packet* server_window, int left_window_index, int sockfd, struct sockaddr * & client_addr) {
    uint32_t packet_number = ntohl(packet->packet_number);
    uint32_t last_ack_number = server_window[left_window_index].packet_number;

    Packet ack_packet = {0};

    if (packet_number == last_ack_number + 1) {
        ack_packet.acknowledgment_number = htonl(last_ack_number + 1);
        // TODO: Verify sendto works
        sendto(sockfd, &ack_packet, sizeof(ack_packet), 0, (struct sockaddr *)&client_addr, client_addr_len);
        return packet_number;
    } else {
        // Packet out of order or duplicate, send the last ACK again
        ack_packet.acknowledgment_number = htonl(last_ack_number + 1);
        // TODO: Verify sendto works
        sendto(sockfd, &ack_packet, sizeof(ack_packet), 0, (struct sockaddr *)&client_addr, client_addr_len);
        return last_ack_number;
    }
}

void update_window(Packet *client_packet, Packet* server_window, int left_pointer, int right_pointer){
    uint32_t client_packet_number = ntohl(client_packet->packet_number);
   if((int) client_packet_number == left_pointer){
        while(server_window[left_pointer] != NULL){
            
        }
   }    
}