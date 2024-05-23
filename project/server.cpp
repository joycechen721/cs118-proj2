#include <iostream>
#include <sys/socket.h> // Socket interface
#include <arpa/inet.h> // Internet protocol
#include <string.h> // strlen
#include <unistd.h> // close, etc.
#include <errno.h> // Get errorno
// ./server server <flag> <port> <private_key_file> <certificate_file>
#include <stdio.h>

int checkFiles(int flag, FILE *pkey , FILE *cert) {
    if (flag == 1) {
        if (pkey == NULL || cert == NULL) {
            fprintf(stderr, "One or more files (private key or certificate file) could not be opened.\n");

            // Close the file that was successfully opened (if any)
            if (pkey != NULL) {
                fclose(pkey);
            }
            if (cert != NULL) {
                fclose(cert);
            }

            return 0; // File is not valid
        } else {
            // If both files are successfully opened
            return 1; // Both files are valid
        }
    }
    return 0; // Default return if flag is not 1
}

int main(int argc, char *argv[])
{
    std::cout << "This is the server implementation!" << std::endl;
    // Parse the arguments

    // Check if the number of arguments is correct
    if (argc != 3 && argc != 5) {
        fprintf(stderr, "One or more files could not be opened.\n");
        return 1;
    }
    int flag = atoi(argv[1]);
    int port = atoi(argv[2]);
    char *private_key_file = NULL;
    char *certificate_file = NULL;
    if (flag == 1) {
        if (argc != 5) {
            fprintf(stderr, "Error: When flag is 1, both private_key_file and certificate_file must be provided.\n");
            return 1;
        }
        private_key_file = argv[3];
        certificate_file = argv[4];
    } 
    //regular stuff
    else if (flag == 0) {
        if (argc != 3) {
            fprintf(stderr, "Error: When flag is 0, no additional files should be provided.\n");
            return 1;
        }
    } else {
        fprintf(stderr, "Error: Flag must be either 0 or 1.\n");
        return 1;
    }

    // check files
    FILE *pkey = fopen(private_key_file, "r");
    FILE *cert = fopen(certificate_file, "r");
    int result = checkFiles(flag, pkey, cert);

    if (!result) {
        fprintf(stderr, "OneExiting.\n");
        return 1;
    }

    /* 1. Create socket */
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0); // use IPv4  use UDP
    /* 2. Construct our address */
    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET; // use IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY; // accept all connections
                            // same as inet_addr("0.0.0.0") 
                                    // "Address string to network bytes"
    // Set receiving port
    int PORT = 8080;
    servaddr.sin_port = htons(PORT); // Big endian

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

    /* 5. Listen for data from clients */
    int bytes_recvd = recvfrom(sockfd, client_buf, BUF_SIZE, 
                            // socket  store data  how much
                              0, (struct sockaddr*) &clientaddr, 
                              &clientsize);
    // Execution will stop here until `BUF_SIZE` is read or termination/error
    // Error if bytes_recvd < 0 :(
    if (bytes_recvd < 0) return errno;

    /* 6. Inspect data from client */
    char* client_ip = inet_ntoa(clientaddr.sin_addr);
                    // "Network bytes to address string"
    int client_port = ntohs(clientaddr.sin_port); // Little endian

    /* 7. Send data back to client */
    char server_buf[] = "Hello world!";
    int did_send = sendto(sockfd, server_buf, strlen(server_buf), 
                      // socket  send data   how much to send
                          0, (struct sockaddr*) &clientaddr, 
                      // flags   where to send
                          sizeof(clientaddr));

    /* 8. You're done! Terminate the connection */     
    close(sockfd);

    //include security stuff
    fclose(pkey);
    fclose(cert);
  
  return 0;
}
