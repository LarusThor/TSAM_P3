#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>
#include <string>
#include <unistd.h>
#include <sstream>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <vector>


using namespace std;

void evilBit(const char* signature_buffer, int sock, sockaddr_in server_addr, int port2) {

    int rawsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (rawsock < 0) { 
        perror("raw socket failed"); exit(1); }
    
    int one = 1;
    if (setsockopt(rawsock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt failed!");
    } 

    // Setup local address so both raw and udp socket use same port numbers
    sockaddr_in local_addr{};
    socklen_t local_len = sizeof(local_addr);
    if (getsockname(sock, (sockaddr*)&local_addr, &local_len) == -1) {
    perror("getsockname failed");
    
    } else {
        char local_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &local_addr.sin_addr, local_ip_str, sizeof(local_ip_str));

    }
 
    char packetHeader[32];

    int pkt_len = sizeof(struct ip) + sizeof(struct udphdr) + 4;


    struct ip *ipHeader = (struct ip *) packetHeader;
    struct udphdr *udpHeader = (struct udphdr *) (packetHeader + sizeof(struct ip));
    char *data = packetHeader + sizeof(struct ip) + sizeof(struct udphdr);

    ipHeader->ip_hl = 5;
    ipHeader->ip_v = 4;
    ipHeader->ip_tos = 0;
    ipHeader->ip_len = htons(pkt_len);
    ipHeader->ip_id = htons(0);
    ipHeader->ip_off = htons(IP_RF);
    ipHeader->ip_ttl = 64;
    ipHeader->ip_p = 17;
    ipHeader->ip_sum = 0;
    ipHeader->ip_dst.s_addr = inet_addr("130.208.246.98");
    ipHeader->ip_src = local_addr.sin_addr;

    uint16_t local_port = ntohs(local_addr.sin_port);
    udpHeader->uh_sport = htons(local_port);
    udpHeader->uh_dport = htons(port2);
    udpHeader->uh_ulen = htons(sizeof(struct udphdr) + sizeof(int));
    udpHeader->uh_sum = 0;
  
    memcpy(data, signature_buffer + 1, sizeof(int));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = ipHeader->ip_dst.s_addr;
    int sent = sendto(rawsock, packetHeader, pkt_len, 0,
        (sockaddr *)&server_addr, sizeof(server_addr));
    if (sent < 0) {
        perror("sendto failed");
        close(rawsock);
        return;
    }
    
    int new_rec_buffer[69];
    sockaddr_in from_addr{};
    socklen_t from_len = sizeof(from_addr);
    int received = recvfrom(sock, new_rec_buffer, sizeof(new_rec_buffer), 0,
        (sockaddr *)&from_addr, &from_len);
    if (received < 0) {
        std::cout << "received failed evil" << std::endl;
    }

    cout << "Secret port message for evil port: " << endl;
    for (int i = 0; i < received; ++i) {
        printf("%C", (unsigned char)((uint8_t*)new_rec_buffer)[i]);
    }
    cout << '\n';


}

uint16_t checksumCalc(const void* data, size_t length) {
    const uint8_t* b = static_cast<const uint8_t*>(data);
    uint32_t sum = 0;

    while (length > 1) {
        uint16_t word = (b[0] << 8) | b[1];
        sum += word;
        b += 2;
        length -= 2;
    }
    if (length == 1) { 
        uint16_t word = (b[0] << 8);
        sum += word;
    }

    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);

    uint16_t res = static_cast<uint16_t>(~sum);
    if (res == 0) res = 0xFFFF;
    return res;
}

void checkSum(char* signature_buffer, int sock, sockaddr_in server_addr, int port3){
    
    int payload_len = 4;
    uint32_t receivedNumber;
    
    memcpy(&receivedNumber, signature_buffer + 1, sizeof(int));
    
    server_addr.sin_port = htons(port3);
    int sent = sendto(sock, &receivedNumber, sizeof(receivedNumber), 0,
        (sockaddr *)&server_addr, sizeof(server_addr));
    cout << "Checksum amount sent: " << sent << endl;
    
    if (sent < 0) {
        perror("sendto failed");
        close(sock);
        return;
    }

    char third_reply_buffer[470];
    char checksumBytes[2];
    char addressBytes[4];
    
    sockaddr_in from_addr{};
    socklen_t from_len = sizeof(from_addr);
    
    // Store reply in a buffer after sending signature
    int received3 = recvfrom(sock, third_reply_buffer, sizeof(third_reply_buffer), 0,
        (sockaddr *)&from_addr, &from_len);
    cout << "Amount received for checksum first receive: " << received3 << endl;
    if (received3 < 0) {
        std::cout << "received failed" << std::endl;
    } else {
        cout << "Checksum first receive: " << third_reply_buffer << endl;
        // Read last 6 bytes into a useful buffer since values change each run
        memcpy(checksumBytes, third_reply_buffer + (received3 - 6), 2);
        memcpy(addressBytes, third_reply_buffer + (received3 - 4), 4);
    }

    cout << "Checksum bytes in network order: " << endl;
    for(int i = 0; i < 2; i++){
        printf("%02X ", (unsigned char)checksumBytes[i]);
    }

    cout << "Ip Address bytes in network order: " << endl;
    for(int i = 0; i < 4; i++){
        printf("%02X ", (unsigned char)addressBytes[i]);
    }

    // Convert the address bytes to a string that is used as src addr in Ipv4 packet header
    char ipString[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, addressBytes, ipString, INET_ADDRSTRLEN);
    std::string addrString(ipString);

    cout << "The address: " << addrString << endl;

    char encapsulatedPacket[1024];
    char packetHeader[32];

    int pkt_len = sizeof(struct ip) + sizeof(struct udphdr) + payload_len;

    sockaddr_in local_addr{};
    socklen_t local_len = sizeof(local_addr);
    
    if(connect(sock,(struct sockaddr*)&server_addr, sizeof(server_addr)) == -1){
        perror("connect failed"); 
    } else {
        if (getsockname(sock, (sockaddr*)&local_addr, &local_len) == -1) {
            perror("getsockname failed");
            } else {
                char local_ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &local_addr.sin_addr, local_ip_str, sizeof(local_ip_str));
        }
    }

    struct ip *ipHeader = (struct ip *) packetHeader;
    struct udphdr *udpHeader = (struct udphdr *) (packetHeader + sizeof(struct ip));
    char *data = packetHeader + sizeof(struct ip) + sizeof(struct udphdr);

    ipHeader->ip_hl = 5;
    ipHeader->ip_v = 4;
    ipHeader->ip_tos = 0;
    ipHeader->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + payload_len);
    ipHeader->ip_id = htons(0);
    ipHeader->ip_ttl = 64;
    ipHeader->ip_p = 17;
    ipHeader->ip_off = 0;
    ipHeader->ip_sum = 0;
    ipHeader->ip_dst.s_addr = inet_addr("130.208.246.98");
    ipHeader->ip_src.s_addr = inet_addr(ipString);

    udpHeader->uh_sport = 54321;
    udpHeader->uh_dport = htons(port3);
    udpHeader->uh_ulen = htons(sizeof(struct udphdr) + 4);
    udpHeader->uh_sum = 0;

    uint8_t pseudoHeader[12];
    memcpy(pseudoHeader + 0, &ipHeader->ip_src, 4);
    memcpy(pseudoHeader + 4, &ipHeader->ip_dst, 4);
    pseudoHeader[8] = 0;
    pseudoHeader[9] = 17;
    
    uint16_t udpLen = htons(sizeof(struct udphdr) + payload_len);
    memcpy(pseudoHeader + 10, &udpLen, 2);
    
    // Add all headers and data for checksum calculations
    std::vector<uint8_t> buf(sizeof(pseudoHeader) + sizeof(struct udphdr) + payload_len);

    memcpy(data, signature_buffer + 1, 4);
    memcpy(buf.data(), pseudoHeader, sizeof(pseudoHeader));
    struct udphdr udpTemp = *udpHeader;
    udpTemp.uh_sum = 0;
    memcpy(buf.data() + sizeof(pseudoHeader), &udpTemp, sizeof(udpTemp));
    memcpy(buf.data() + sizeof(pseudoHeader) + sizeof(udpTemp), data, payload_len);

    // Mimmic udp checksum to valid server requested udp checksum
    uint16_t serverChecksum;
    memcpy(&serverChecksum, checksumBytes, sizeof(serverChecksum));
    serverChecksum = ntohs(serverChecksum);
    cout << "Server checksum should be: " << serverChecksum << endl;

    // Loop to check if updated payload changed checksum so it matches requested
    bool found = false;
    int brute_index = payload_len - 1;
    for (int b = 0; b < 256 && !found; ++b) {
        data[brute_index] = (uint8_t)b;
        // Copy changed payload into buf
        memcpy(buf.data() + sizeof(pseudoHeader) + sizeof(udpTemp), data, payload_len);
        uint16_t udp_sum = checksumCalc(buf.data(), buf.size()); // host order
        if (udp_sum == serverChecksum) {
            cout << "There was a match" << endl;
            udpHeader->uh_sum = htons(udp_sum);
            found = true;
            break;
        }
    }

    if (!found && payload_len >= 2) {
    for (int b1 = 0; b1 < 256 && !found; ++b1) {
        data[payload_len - 2] = (uint8_t)b1;
        for (int b2 = 0; b2 < 256; ++b2) {
            data[payload_len - 1] = (uint8_t)b2;
            memcpy(buf.data() + sizeof(pseudoHeader) + sizeof(udpTemp), data, payload_len);
            uint16_t udp_sum = checksumCalc(buf.data(), buf.size());
            if (udp_sum == serverChecksum) {
                cout << "Found in second try" << endl;
                udpHeader->uh_sum = htons(udp_sum);
                found = true;
                break;
            }
        }
    }
}

    memcpy(encapsulatedPacket, packetHeader, pkt_len);
    timeval tv{.tv_sec = 2, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int sent2 = send(sock, encapsulatedPacket, pkt_len, 0);
    if (sent2 < 0) {
        perror("sendto failed");
        close(sock);
        return;
    }

    char rec_buffer[1024];
    int received = recvfrom(sock, rec_buffer, sizeof(rec_buffer), 0,
        (sockaddr *)&from_addr, &from_len);
    if (received < 0) {
        std::cout << "received failed" << std::endl;
    }
    cout << "RECEIVED FROM BUFFER IN CHECKSUM:" << endl;
    cout << rec_buffer << endl;
    
}


void EXPSTN(char* signature_buffer, int sock, sockaddr_in server_addr, int port4){
    
    std::string secret_ports = "4010,4096"; //Secret ports we got from from previous puzzles
    char buffer[20];
    memcpy(buffer, secret_ports.data(), secret_ports.size());
    int totalLen = secret_ports.size();
    server_addr.sin_port = htons(port4);

    //Send the secret ports to port nr. 4
    int sent = sendto(sock, buffer, totalLen, 0,
        (sockaddr *)&server_addr, sizeof(server_addr));
    if (sent < 0) {
        perror("sendto failed");
        close(sock);
        return;
    }

    //Receive the order of the ports as response
    char rec_buffer[29];
    sockaddr_in from_addr{};
    socklen_t from_len = sizeof(from_addr);
    from_addr.sin_port = htons(port4);
    int received = recvfrom(sock, rec_buffer, sizeof(rec_buffer), 0,
        (sockaddr *)&from_addr, &from_len);
    if (received < 0) {
        perror("received from port4 failed: ");
    }
    
    
    //Put every port number into an array for easy access
    std::string data(rec_buffer);
    std::vector<int> portSequence;
    std::stringstream ss(data);
    std::string token;
    while (std::getline(ss, token, ',')) {
        portSequence.push_back(std::stoi(token));
    }

    //Send the signature and secret phrase to all 6 ports in right order
    std::string replyString;
    for (int i = 0; i < portSequence.size(); i++) {
        std::string phrase;
        phrase = "A fool thinks themselves to be wise, but the wise know themselves to be fools."; 
        std::vector<char> phraseBuffer(4 + phrase.size());
        memcpy(phraseBuffer.data(), signature_buffer + 1, 4);
        memcpy(phraseBuffer.data() + 4, phrase.data(), phrase.size());
 
        server_addr.sin_port = htons(portSequence[i]);
        int sent2 = sendto(sock, phraseBuffer.data(), (int)phraseBuffer.size(), 0,
            (sockaddr *)&server_addr, sizeof(server_addr));
        if (sent2 < 0) {
            perror("sendto failed");
            close(sock);
            return;
        }
        
        char knockRecBuffer[1024];
        sockaddr_in raddr{}; 
        socklen_t rlen = sizeof(raddr);
        
        int reply = recvfrom(sock, knockRecBuffer, sizeof(knockRecBuffer), 0,
            (sockaddr *)&raddr, &rlen);
        if (reply < 0) { perror("receive failed "); break;}
        std::string replyStr(knockRecBuffer, knockRecBuffer + reply);
        cout << "Received from port number " << portSequence[i] << ":" << endl;
        cout << replyStr  << endl;
    }

   
}


std::string secret(int sock, sockaddr_in server_addr, int port1) {
    
    server_addr.sin_port = htons(port1);
    std::string names = "larus23,steinars23"; // RU names
    int secretNumber = 32500; // Secret number that we decided
    
    // Buffer with first Byte as 'S' and the rest is the secret number
    char buffer[1024];
    buffer[0] = 'S';
    uint32_t netSecret = htonl(secretNumber);
    memcpy(buffer + 1, &netSecret, sizeof(netSecret));
    memcpy(buffer + 1 + sizeof(netSecret), names.data(), names.size());
    
    int totalLen = 1 + sizeof(netSecret) + names.size();

    // Send the Buffer to server
    int sent = sendto(sock, buffer, totalLen, 0,
        (sockaddr *)&server_addr, sizeof(server_addr));
    if (sent < 0) {
        perror("sendto failed");
        close(sock);
        return nullptr;
    }

    // Receive reply from server
    char rec_buffer[5];
    sockaddr_in from_addr{};
    socklen_t from_len = sizeof(from_addr);
    int received = recvfrom(sock, rec_buffer, sizeof(rec_buffer), 0,
        (sockaddr *)&from_addr, &from_len);
    if (received < 0) {
        std::cout << "received failed" << std::endl;
    }

    // for (int i = 0; i < sizeof(int) + sizeof(char); i++) {
    //     int numb = rec_buffer[i];
    //     std::cout << numb << endl;
    // }
   
    // std::cout << '\n';
    int receivedNumber;
    int groupID = rec_buffer[0];
    
    memcpy(&receivedNumber, rec_buffer + 1, sizeof(receivedNumber));
    receivedNumber = ntohl(receivedNumber); 
    receivedNumber = receivedNumber ^ secretNumber;
    receivedNumber = htonl(receivedNumber);

    char signature_buffer[5];
    signature_buffer[0] = groupID;
    memcpy(signature_buffer + 1, &receivedNumber, sizeof(receivedNumber));
    for (size_t i = 0; i < 5; i++)
    {
        std::cout << (int)signature_buffer[i];
    }
    std::cout << std::endl;

    int sent2 = sendto(sock, signature_buffer, sizeof(signature_buffer), 0,
        (sockaddr *)&server_addr, sizeof(server_addr));
    if (sent2 < 0) {
        perror("signatureBuffer failed");
        close(sock);
        return nullptr;
    }

    //Second reply
    char second_reply_buffer[70];
 
    int received2 = recvfrom(sock, second_reply_buffer, sizeof(second_reply_buffer), 0,
        (sockaddr *)&from_addr, &from_len);
    //std::cout << "Received amount: " << received2 << std::endl;
    if (received2 < 0) {
        std::cout << "received failed" << std::endl;
    }

    std::cout << "Second reply buffer: " << second_reply_buffer << std::endl;
    return std::string(signature_buffer);


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

    timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    

    std::string signature_buffer = secret(sock, server_addr, port1);
    
    evilBit(signature_buffer.c_str(), sock, server_addr, port2);

    //checkSum(signature_buffer, sock, server_addr, port3);

    //EXPSTN(signature_buffer, sock, server_addr, port4);
    //delete[] signature_buffer;

    return 0;

}