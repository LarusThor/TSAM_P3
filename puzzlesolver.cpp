#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>
#include <string>
#include <unistd.h>

using namespace std;


void evilBit(char* signature_buffer, int sock, sockaddr_in server_addr, int port2) {
    //TODO: Figure out how to send correctly and receive messages
    server_addr.sin_port = htons(port2);
    int sent = sendto(sock, signature_buffer, sizeof(signature_buffer), 0,
        (sockaddr *)&server_addr, sizeof(server_addr));
    if (sent < 0) {
        perror("sendto failed");
        close(sock);
        return;
    }
    int rec_buffer[1024];
    sockaddr_in from_addr{};
    socklen_t from_len = sizeof(from_addr);
    int received = recvfrom(sock, rec_buffer, sizeof(rec_buffer), 0,
        (sockaddr *)&from_addr, &from_len);
    std::cout << "Received amount for first evil reply: " << received << std::endl;
    if (received < 0) {
        std::cout << "received failed" << std::endl;
    }

    std::cout << "Received buffer: " << std::endl;
    for (int i = 0; i < sizeof(rec_buffer); i++) {
        printf("%02X ", (unsigned char)rec_buffer[i]);
    }

}


int main(int argc, char *argv[]) {
    if (argc != 6) {
        perror("Incorrect amount of arguments");
        exit(0);
    }

    int sock; 
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("Socket creation failed");
        exit(0);
    }
    char* ip_string = argv[1];
    int port1 = std::stoi(argv[2]);
    int port2 = std::stoi(argv[3]);
    int port3 = std::stoi(argv[4]);
    int port4 = std::stoi(argv[5]);

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip_string, &server_addr.sin_addr) != 1) {
        std::cout << "IP address is weird" << std::endl;
    } 
    
    server_addr.sin_port = htons(port1);
    std::string names = "larus23,steinars23";
    int secretNumber = 32500;

    char buffer[1024];
    buffer[0] = 'S';

    uint32_t netSecret = htonl(secretNumber);
    memcpy(buffer + 1, &netSecret, sizeof(netSecret));
    memcpy(buffer + 1 + sizeof(netSecret), names.data(), names.size());

    int totalLen = 1 + sizeof(netSecret) + names.size();
    for (int i = 0; i < totalLen; i++) {
        printf("%02X ", (unsigned char)buffer[i]);
    }
    printf("\n");
    

    int sent = sendto(sock, buffer, totalLen, 0,
        (sockaddr *)&server_addr, sizeof(server_addr));
    if (sent < 0) {
        perror("sendto failed");
        close(sock);
        return 1;
    }

    timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char rec_buffer[5];
    sockaddr_in from_addr{};
    socklen_t from_len = sizeof(from_addr);
    int received = recvfrom(sock, rec_buffer, sizeof(rec_buffer), 0,
        (sockaddr *)&from_addr, &from_len);
    std::cout << "Received amount for first reply: " << received << std::endl;
    if (received < 0) {
        std::cout << "received failed" << std::endl;
    }

    for (int i = 0; i < sizeof(int) + sizeof(char); i++) {
        int numb = rec_buffer[i];
        std::cout << numb << endl;
    }
   
    std::cout << '\n';
    int receivedNumber;
    int groupID = rec_buffer[0];
    
    memcpy(&receivedNumber, rec_buffer + 1, sizeof(receivedNumber));
    receivedNumber = ntohl(receivedNumber); 
    receivedNumber = receivedNumber ^ secretNumber;
    receivedNumber = htonl(receivedNumber);
    std::cout << "Group Id: " << groupID << std::endl;
    std::cout << "Challenger number: " << receivedNumber << std::endl;
    std::cout << '\n';

    char signature_buffer[5];
    signature_buffer[0] = groupID;
    std::cout << "Group ID: " << groupID << std::endl;
    std::cout << "Signature buffer: " << std::endl;

    
    memcpy(signature_buffer + 1, &receivedNumber, sizeof(receivedNumber));
    for (size_t i = 0; i < 5; i++)
    {
        std::cout << (int)signature_buffer[i];
    }
    std::cout << std::endl;

    for (int i = 0; i < 5; i++) {
        printf("Last signature buffer: %02X \n", (unsigned char)signature_buffer[i]);
    }

    cout << "total lenght when sending 2nd time: " << totalLen << endl;

    int sent2 = sendto(sock, signature_buffer, sizeof(signature_buffer), 0,
        (sockaddr *)&server_addr, sizeof(server_addr));
    if (sent2 < 0) {
        perror("signatureBuffer failed");
        close(sock);
        return 1;
    }

    //Second reply
    char second_reply_buffer[69];
 
    int received2 = recvfrom(sock, second_reply_buffer, sizeof(second_reply_buffer), 0,
        (sockaddr *)&from_addr, &from_len);
    std::cout << "Received amount: " << received2 << std::endl;
    if (received2 < 0) {
        std::cout << "received failed" << std::endl;
    }

    std::cout << "Second reply buffer: " << second_reply_buffer << std::endl;
    std::cout << std::endl;

    evilBit(signature_buffer, sock, server_addr, port2);

    return 0;

}