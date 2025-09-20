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
    tv.tv_usec = 100000; // 100 ms
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char rec_buffer[5];
    sockaddr_in from_addr{};
    socklen_t from_len = sizeof(from_addr);
    int received = recvfrom(sock, rec_buffer, sizeof(rec_buffer) - 1, 0,
        (sockaddr *)&from_addr, &from_len);
    
    if (received < 0) {
        std::cout << "received failed" << std::endl;
    }

    for (int i = 0; i < sizeof(int) + sizeof(char); i++) {
        int numb = rec_buffer[i];
        std::cout << numb;
    }

    std::cout << rec_buffer << endl;
    std::cout << '\n';
    int receivedNumber;
    int groupID = rec_buffer[0];
    
    memcpy(&receivedNumber, rec_buffer + 1, sizeof(receivedNumber));
    receivedNumber = receivedNumber ^ secretNumber;
    std::cout << "Group Id: " << groupID << std::endl;
    std::cout << "Challenger number: " << receivedNumber << std::endl;
    std::cout << '\n';

    char signature_buffer[5];
    signature_buffer[0] = groupID;
    memcpy(signature_buffer + 1, &receivedNumber, sizeof(receivedNumber));

    int sent2 = sendto(sock, signature_buffer, totalLen, 0,
        (sockaddr *)&server_addr, sizeof(server_addr));
    if (sent2 < 0) {
        perror("signatureBuffer failed");
        close(sock);
        return 1;
    }

    //Second reply
    char second_reply_buffer[1024];
 
    int received2 = recvfrom(sock, second_reply_buffer, sizeof(second_reply_buffer) - 1, 0,
        (sockaddr *)&from_addr, &from_len);
    
    if (received2 < 0) {
        std::cout << "received failed" << std::endl;
    }

     for (int i = 0; i < sizeof(short); i++) {
        int numb = second_reply_buffer[i];
        std::cout << numb;
    }
    std::cout << std::endl;
    std::cout << second_reply_buffer << endl;
    
    //std::cout <<  rec_buffer << std::endl;
                
            
    

    

    return 0;

}