// Created by anomaloushuman - Patrick Garcia
// Email - patrick@ubiquityglass.com
// 12/19/2024 - Sock Server v0.0.1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

const char* sharedKey = "your-very-secure-key";

char* encryptMessage(const char* message) {
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);
    char ivStr[AES_BLOCK_SIZE + 1];
    memcpy(ivStr, iv, AES_BLOCK_SIZE);
    ivStr[AES_BLOCK_SIZE] = '\0';

    unsigned char key[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)sharedKey, strlen(sharedKey), key);

    AES_KEY aes_key;
    AES_set_encrypt_key(key, 256, &aes_key);

    int len = strlen(message), written = 0;
    char* encrypted = (char*)malloc(len + AES_BLOCK_SIZE + 1);
    memset(encrypted, '\0', len + AES_BLOCK_SIZE + 1);
    AES_cbc_encrypt((unsigned char*)message, (unsigned char*)encrypted, len, &aes_key, iv, AES_ENCRYPT);

    char* encryptedBase64 = Base64::encode((unsigned char*)encrypted, len + AES_BLOCK_SIZE);
    char* result = (char*)malloc(strlen(ivStr) + strlen(encryptedBase64) + 2);
    sprintf(result, "%s:%s", ivStr, encryptedBase64);
    free(encryptedBase64);
    free(encrypted);
    return result;
}

char* generateHMAC(const char* message) {
    unsigned char key[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)sharedKey, strlen(sharedKey), key);

    unsigned char hmac[SHA256_DIGEST_LENGTH];
    HMAC(EVP_sha256(), key, SHA256_DIGEST_LENGTH, (unsigned char*)message, strlen(message), hmac, nullptr);

    char* hmacBase64 = Base64::encode(hmac, SHA256_DIGEST_LENGTH);
    return hmacBase64;
}

int main() {
    int sockfd, connfd;
    struct sockaddr_in servaddr, cli;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        fprintf(stderr, "Socket creation failed...\n");
        return -1;
    }

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(9000);

    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0) {
        fprintf(stderr, "Connection with the server failed...\n");
        return -1;
    }

    char* handshakeMessage = "HELLO SERVER";
    sendMessage(handshakeMessage, sockfd);

    char buffer[1024] = {0};
    int n;
    while ((n = read(sockfd, buffer, 1024)) > 0) {
        printf("Received: %.*s\n", n, buffer);
    }

    close(sockfd);
    return 0;
}

void sendMessage(const char* message, int sockfd) {
    char* encryptedMessage = encryptMessage(message);
    char* hmac = generateHMAC(encryptedMessage);
    char* payload = (char*)malloc(strlen(hmac) + strlen(encryptedMessage) + 3);
    sprintf(payload, "%s:%s\r\n", hmac, encryptedMessage);
    send(sockfd, payload, strlen(payload), 0);
    free(payload);
    free(hmac);
    free(encryptedMessage);
}
