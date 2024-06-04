# CS118 Project 2

This is the repo for spring24 cs118 project 2.

## Academic Integrity Note

You are encouraged to host your code in private repositories on [GitHub](https://github.com/), [GitLab](https://gitlab.com), or other places.  At the same time, you are PROHIBITED to make your code for the class project public during the class or any time after the class.  If you do so, you will be violating academic honestly policy that you have signed, as well as the student code of conduct and be subject to serious sanctions.

## Provided Files

- `project` is folder to develop codes for future projects.
- `docker-compose.yaml` and `Dockerfile` are files configuring the containers.

## Bash commands

```bash
# Setup the container(s) (make setup)
docker compose up -d

# Bash into the container (make shell)
docker compose exec node1 bash

# Remove container(s) and the Docker image (make clean)
docker compose down -v --rmi all --remove-orphans
```

## Environment

- OS: ubuntu 22.04
- IP: 192.168.10.225. NOT accessible from the host machine.
- Port forwarding: container 8080 <-> host 8080
  - Use http://localhost:8080 to access the HTTP server in the container.
- Files in this repo are in the `/project` folder. That means, `server.c` is `/project/project/server.c` in the container.

## TODO -- Project Report

  ### Team Members:
  - Gautam Anand, 405965589
  - Joyce Chen, 405935837
  - Daniel Kao, 005533941

  ### High Level Design:
  We implemented the server and client the same way, with the only differences being the security handshake portion. 
  - Structures:
    - we had structs that modelled the formats of every type of Packet we were sending
    - ie. Packet, Certificate, KeyExchange, ServerHello structs
    - we have a char data[0] field at the end of each struct to account for variable length data in relevant packets
  - Reliable transport layer:
    - make stdin and socket non-blocking, so we can read data from stdin and send/receive from socket simultaneously in 1 while loop
  - Handling data from stdin:
    - have an "input buffer window" with left/current/right pointers to indicate the oldest unacked Packet, the current Packet we're sending, and the packet # we can send up to
    - purpose of input buffer is for retransmission, in case we don't get an ack for it on time
    - right - left pointer is always 20, for congestion control
    - only when our current Packet is between left/right pointer, do we read from stdin, package bytes into a Packet, store its pointer into our input buffer, and send it through the socket
  - Handling incoming data from socket:
    - buffer to store incoming data, so that we can order the packets in case some get lost
    - if receive an ack, set the left pointer of the input buffer to the current packet #, and move right pointer to left + 20, so we can transmit new data we read in! acks are cummulative.
  - Security layer
    - if statements to check whether we are in the handshake phase, and handled the packets correspondingly
    - if statements for mac code as well
  
  ### Problems we ran into + How we solved them:
  We ran into plenty of problems during our implementation. In fact, we probably spent more time debugging than actually writing out the logic.
  - verification of signatures not working in the handshake
    - redid pointer math for our structs and mallocs, ensuring that the correct data is being stored into the structs and sent across
    - printed out every data field and manually checked if the pakcet bytes were the same on both sending and receiving sides
  - not handling variable length data properly
    - realized that we weren't structuring our packet structs properly, and we were instead allocating fixed size buffers
    - had to look into mallocs and how C supports variable sized buffers in structs
  - large binary files not transmitting
    - realized it was an issue with the acks and data transmission logic
    - had to encapsulate acks and data into 1 packet
  - tests not running correctly against reference client/server
    - found out that we were passing data without using network byte order, which the reference client/server on the autograder uses
    - had to convert all 2-byte and 4-byte integers to network byte order using ntohs/ntohl and htons/htonl


  ### Source acknowledgements:
  - Tutorialspoint, GeeksforGeeks, cppreference.com, Stack Overflow




