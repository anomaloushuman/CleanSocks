// Created by anomaloushuman - Patrick Garcia
// Email - patrick@ubiquityglass.com
// 12/19/2024 - Sock Server v0.0.1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

char* serverKey = "your-very-secure-key"; // Shared secret key for HMAC and encryption

SSL_CTX* createServerContext() {
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_use_certificate_file(ctx, "/path/to/server_cert.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "/path/to/server_key.pem", SSL_FILETYPE_PEM);
    SSL_CTX_check_private_key(ctx);
    SSL_CTX_load_verify_locations(ctx, "/path/to/ca_cert.pem", NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    return ctx;
}

void handleClient(SSL* ssl) {
    printf("Client connected\n");

    // Handshake
    SSL_write(ssl, "HELLO CLIENT\r\n", 14);
    char response[1024];
    SSL_read(ssl, response, 1024);
    if (strcmp(response, "HELLO SERVER") != 0) {
        SSL_write(ssl, "ERROR: INVALID HANDSHAKE\r\n", 26);
        SSL_shutdown(ssl);
        return;
    }

    SSL_write(ssl, "HANDSHAKE COMPLETE\r\n", 21);

    char data[2048];
    SSL_read(ssl, data, 2048);
    char* hmac = strtok(data, ":");
    char* encryptedMessage = strtok(NULL, ":");
    if (!verifyHmac(encryptedMessage, hmac, serverKey)) {
        SSL_write(ssl, "ERROR: INVALID MESSAGE\r\n", 26);
        return;
    }

    char* message = decryptMessage(encryptedMessage, serverKey);
    printf("Received: %s\n", message);

    char* response = "You sent: ";
    char* encryptedResponse = encryptMessage(response, serverKey);
    char* responseHmac = generateHmac(encryptedResponse, serverKey);

    SSL_write(ssl, (responseHmac + ":" + encryptedResponse + "\r\n"), strlen(responseHmac) + strlen(encryptedResponse) + 4);
}

int main() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX* ctx = createServerContext();
    if (!ctx) {
        fprintf(stderr, "Error creating server context\n");
        return 1;
    }

    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) {
        fprintf(stderr, "Error creating server socket\n");
        return 1;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(9000);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        fprintf(stderr, "Error binding server socket\n");
        return 1;
    }

    if (listen(server, 5) < 0) {
        fprintf(stderr, "Error listening on server socket\n");
        return 1;
    }

    while (1) {
        struct sockaddr_in clientAddr;
        socklen_t clientAddrSize = sizeof(clientAddr);
        int client = accept(server, (struct sockaddr*)&clientAddr, &clientAddrSize);
        if (client < 0) {
            fprintf(stderr, "Error accepting client connection\n");
            continue;
        }

        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);
        if (SSL_accept(ssl) <= 0) {
            fprintf(stderr, "Error accepting SSL connection\n");
            continue;
        }

        handleClient(ssl);

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }

    close(server);
    SSL_CTX_free(ctx);
    return 0;
}

char* encryptMessage(char* message, char* key) {
    unsigned char iv[16];
    RAND_bytes(iv, 16);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)key, iv);
    EVP_EncryptUpdate(ctx, (unsigned char*)message, NULL, (unsigned char*)message, strlen(message));
    unsigned char encrypted[strlen(message) + 16];
    int len;
    EVP_EncryptFinal_ex(ctx, encrypted, &len);
    EVP_CIPHER_CTX_free(ctx);
    char* encryptedMessage = (char*)malloc(strlen(message) + 16 + 1);
    memcpy(encryptedMessage, iv, 16);
    memcpy(encryptedMessage + 16, encrypted, len);
    encryptedMessage[len + 16] = '\0';
    return encryptedMessage;
}

char* decryptMessage(char* data, char* key) {
    unsigned char iv[16];
    memcpy(iv, data, 16);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)key, iv);
    EVP_DecryptUpdate(ctx, (unsigned char*)data, NULL, (unsigned char*)data, strlen(data));
    unsigned char decrypted[strlen(data) - 16];
    int len;
    EVP_DecryptFinal_ex(ctx, decrypted, &len);
    EVP_CIPHER_CTX_free(ctx);
    char* decryptedMessage = (char*)malloc(len + 1);
    memcpy(decryptedMessage, decrypted, len);
    decryptedMessage[len] = '\0';
    return decryptedMessage;
}

char* generateHmac(char* data, char* key) {
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int len;
    HMAC(EVP_sha256(), key, strlen(key), (unsigned char*)data, strlen(data), hmac, &len);
    char* hmacString = (char*)malloc(len + 1);
    memcpy(hmacString, hmac, len);
    hmacString[len] = '\0';
    return hmacString;
}

bool verifyHmac(char* data, char* hmac, char* key) {
    char* generatedHmac = generateHmac(data, key);
    return strcmp(generatedHmac, hmac) == 0;
}