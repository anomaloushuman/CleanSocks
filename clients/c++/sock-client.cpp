// Created by anomaloushuman - Patrick Garcia
// Email - patrick@ubiquityglass.com
// 12/19/2024 - Sock Server v0.0.1

#include <iostream>
#include <string>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

const std::string sharedKey = "your-very-secure-key";

std::string encryptMessage(const std::string& message) {
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);
    std::string ivStr((char*)iv, AES_BLOCK_SIZE);

    unsigned char key[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)sharedKey.c_str(), sharedKey.size(), key);

    AES_KEY aes_key;
    AES_set_encrypt_key(key, 256, &aes_key);

    int len = message.size(), written = 0;
    std::string encrypted;
    encrypted.resize(len + AES_BLOCK_SIZE, '\0');
    AES_cbc_encrypt((unsigned char*)message.c_str(), (unsigned char*)&encrypted[0], len, &aes_key, iv, AES_ENCRYPT);

    std::string encryptedBase64 = Base64::encode((unsigned char*)&encrypted[0], len + AES_BLOCK_SIZE);
    return ivStr + ":" + encryptedBase64;
}

std::string generateHMAC(const std::string& message) {
    unsigned char key[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)sharedKey.c_str(), sharedKey.size(), key);

    unsigned char hmac[SHA256_DIGEST_LENGTH];
    HMAC(EVP_sha256(), key, SHA256_DIGEST_LENGTH, (unsigned char*)message.c_str(), message.size(), hmac, nullptr);

    std::string hmacBase64 = Base64::encode(hmac, SHA256_DIGEST_LENGTH);
    return hmacBase64;
}

int main() {
    int sockfd, connfd;
    struct sockaddr_in servaddr, cli;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        std::cerr << "Socket creation failed..." << std::endl;
        return -1;
    }

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(9000);

    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0) {
        std::cerr << "Connection with the server failed..." << std::endl;
        return -1;
    }

    std::string handshakeMessage = "HELLO SERVER";
    sendMessage(handshakeMessage, sockfd);

    char buffer[1024] = {0};
    int n;
    while ((n = read(sockfd, buffer, 1024)) > 0) {
        std::string data(buffer, n);
        std::cout << "Received: " << data << std::endl;
    }

    close(sockfd);
    return 0;
}

void sendMessage(const std::string& message, int sockfd) {
    std::string encryptedMessage = encryptMessage(message);
    std::string hmac = generateHMAC(encryptedMessage);
    std::string payload = hmac + ":" + encryptedMessage + "\r\n";

    send(sockfd, payload.c_str(), payload.size(), 0);
}
