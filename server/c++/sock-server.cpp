// Created by anomaloushuman - Patrick Garcia
// Email - patrick@ubiquityglass.com
// 12/19/2024 - Sock Server v0.0.1

#include <iostream>
#include <fstream>
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

std::string serverKey = "your-very-secure-key"; // Shared secret key for HMAC and encryption

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
    std::cout << "Client connected" << std::endl;

    // Handshake
    SSL_write(ssl, "HELLO CLIENT\r\n", 14);
    char response[1024];
    SSL_read(ssl, response, 1024);
    if (std::string(response) != "HELLO SERVER") {
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

    std::string message = decryptMessage(encryptedMessage, serverKey);
    std::cout << "Received: " << message << std::endl;

    std::string response = "You sent: " + message;
    std::string encryptedResponse = encryptMessage(response, serverKey);
    std::string responseHmac = generateHmac(encryptedResponse, serverKey);

    SSL_write(ssl, (responseHmac + ":" + encryptedResponse + "\r\n").c_str(), responseHmac.length() + encryptedResponse.length() + 4);
}

int main() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX* ctx = createServerContext();
    if (!ctx) {
        std::cerr << "Error creating server context" << std::endl;
        return 1;
    }

    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) {
        std::cerr << "Error creating server socket" << std::endl;
        return 1;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(9000);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Error binding server socket" << std::endl;
        return 1;
    }

    if (listen(server, 5) < 0) {
        std::cerr << "Error listening on server socket" << std::endl;
        return 1;
    }

    while (1) {
        struct sockaddr_in clientAddr;
        socklen_t clientAddrSize = sizeof(clientAddr);
        int client = accept(server, (struct sockaddr*)&clientAddr, &clientAddrSize);
        if (client < 0) {
            std::cerr << "Error accepting client connection" << std::endl;
            continue;
        }

        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);
        if (SSL_accept(ssl) <= 0) {
            std::cerr << "Error accepting SSL connection" << std::endl;
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

std::string encryptMessage(std::string message, std::string key) {
    unsigned char iv[16];
    RAND_bytes(iv, 16);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)key.c_str(), iv);
    EVP_EncryptUpdate(ctx, (unsigned char*)message.c_str(), NULL, (unsigned char*)message.c_str(), message.length());
    unsigned char encrypted[message.length() + 16];
    int len;
    EVP_EncryptFinal_ex(ctx, encrypted, &len);
    EVP_CIPHER_CTX_free(ctx);
    return std::string((char*)iv, 16) + std::string((char*)encrypted, len);
}

std::string decryptMessage(std::string data, std::string key) {
    unsigned char iv[16];
    memcpy(iv, data.c_str(), 16);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)key.c_str(), iv);
    EVP_DecryptUpdate(ctx, (unsigned char*)data.c_str(), NULL, (unsigned char*)data.c_str(), data.length());
    unsigned char decrypted[data.length() - 16];
    int len;
    EVP_DecryptFinal_ex(ctx, decrypted, &len);
    EVP_CIPHER_CTX_free(ctx);
    return std::string((char*)decrypted, len);
}

std::string generateHmac(std::string data, std::string key) {
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int len;
    HMAC(EVP_sha256(), key.c_str(), key.length(), (unsigned char*)data.c_str(), data.length(), hmac, &len);
    return std::string((char*)hmac, len);
}

bool verifyHmac(std::string data, std::string hmac, std::string key) {
    std::string generatedHmac = generateHmac(data, key);
    return HMAC(EVP_sha256(), key.c_str(), key.length(), (unsigned char*)data.c_str(), data.length(), NULL, NULL) == HMAC(EVP_sha256(), key.c_str(), key.length(), (unsigned char*)data.c_str(), data.length(), NULL, NULL);
}