#include <iostream>
#include <sys/socket.h> // Socket interface
#include <arpa/inet.h> // Internet protocol
#include <string.h> // strlen
#include <unistd.h> // close, etc.
#include <errno.h> // Get errorno

//./client client <flag> <hostname> <port> <ca_public_key_file>
int main(int argc, char *argv[])
{
    std::cout << "This is the client implementation!" << std::endl;

    // Check if the number of arguments is correct
    if (argc != 4 && argc != 5) {
        fprintf(stderr, "Usage: client <flag> <hostname> <port> <ca_public_key_file>\n");
        return 1;
    }
    // Parse the arguments
    int flag = atoi(argv[1]);
    char *hostname = argv[2];
    int port = atoi(argv[3]);
    char *ca_public_key_file = NULL;
    //include security stuff
    if (flag == 1) {
        if (argc != 5) {
            fprintf(stderr, "Error: When flag is 1, a public key file must be provided.\n");
            return 1;
        }
        ca_public_key_file = argv[4];
    } 
    //regular stuff
    else if (flag == 0) {
        if (argc != 4) {
            fprintf(stderr, "Error: When flag is 0, no additional files should be provided.\n");
            return 1;
        }
    } else {
        fprintf(stderr, "Error: Flag must be either 0 or 1.\n");
        return 1;
    }
    // Debug output to verify the values
    printf("Flag: %d\n", flag);
    printf("Port: %d\n", port);
    printf("Hostname: %s\n", hostname);
    if (flag == 1) {
        printf("Public Key File: %s\n", ca_public_key_file);
    }

  /* 1. Create socket */
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
                     // use IPv4  use UDP

    /* 2. Construct server address */
    struct sockaddr_in serveraddr;
    serveraddr.sin_family = AF_INET; // use IPv4
    serveraddr.sin_addr.s_addr = INADDR_ANY;
    // Set sending port
    int SEND_PORT = 8080;
    serveraddr.sin_port = htons(SEND_PORT); // Big endian

    /* 3. Send data to server */
    char client_buf[] = "Hello world!";
    int did_send = sendto(sockfd, client_buf, strlen(client_buf), 
                       // socket  send data   how much to send
                          0, (struct sockaddr*) &serveraddr, 
                       // flags   where to send
                          sizeof(serveraddr));
    if (did_send < 0) return errno;

    /* 4. Create buffer to store incoming data */
    int BUF_SIZE = 1024;
    char server_buf[BUF_SIZE];
    socklen_t serversize; // Temp buffer for recvfrom API

    /* 5. Listen for response from server */
    // while(read(STDIN_FILENO, &ch, 1) > 0)
    // {
    // //do stuff
    // }
    int bytes_recvd = recvfrom(sockfd, server_buf, BUF_SIZE, 
                            // socket  store data  how much
                               0, (struct sockaddr*) &serveraddr, 
                               &serversize);
    // Execution will stop here until `BUF_SIZE` is read or termination/error
    // Error if bytes_recvd < 0 :(
    if (bytes_recvd < 0) return errno;
    // Print out data
    write(1, server_buf, bytes_recvd);


    /* 6. You're done! Terminate the connection */     
    close(sockfd);

    return 0;
}
