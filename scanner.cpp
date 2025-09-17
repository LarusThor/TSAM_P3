//Comment
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

    if (argc != 4) {
        perror("Incorrect amount of arguments");
        exit(0);
    }

    int sock; 
    char* ip_string = argv[1];
    int low_port = std::stoi(argv[2]);
    int high_port = std::stoi(argv[3]);

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("Socket creation failed");
        exit(0);
    }

    timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = 100000; // 100 ms
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt SO_RCVTIMEO");
        close(sock);
        return 1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    
    if (inet_pton(AF_INET, ip_string, &server_addr.sin_addr) != 1) {
        std::cout << "IP address is weird" << std::endl;
    } 
    
    const char *message = "connecting";

    for (int i = low_port; i <= high_port; i++) {
        
        for (int j=0; j<3; j++) {
        server_addr.sin_port = htons(i);
        int sent = sendto(sock, message, strlen(message), 0,
        (sockaddr *)&server_addr, sizeof(server_addr));
        if (sent < 0) {
            perror("sendto failed");
            close(sock);
            return 1;
        }
        
        char buffer[2048];
        sockaddr_in from_addr{};
        socklen_t from_len = sizeof(from_addr);
        int received = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
        (sockaddr *)&from_addr, &from_len);
        
            if (received < 0) {
                continue;
            } else {
                buffer[received] = '\0';
                std::cout << "Port number: " << i << " " << buffer << std::endl;
                break;
            }
        }
  
    }
    
    close(sock);


    return 0;
}