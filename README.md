# CleanSocks

An open-source, cross-platform, secure, extensible, full-duplex custom protocol socket server and client.

## Table of Contents

- [Java Client](#java-client)
- [Kotlin Client](#kotlin-client)
- [JavaScript Client](#javascript-client)
- [C Client](#c-client)
- [C++ Client](#cpp-client)
- [Rust Client](#rust-client)
- [PHP Server](#php-server)
- [License](#license)

## Java Client

### Description
The Java client connects to a secure socket server using a custom protocol. It performs a handshake and sends encrypted messages with HMAC for integrity.

### Compilation Instructions
1. Ensure you have JDK installed.
2. Compile the Java client:
   ```bash
   javac -cp . clients/java/sock-client.java
   ```
3. Run the client:
   ```bash
   java -cp . SecureClient
   ```

## Kotlin Client

### Description
The Kotlin client functions similarly to the Java client, utilizing Kotlin's features for a more concise implementation.

### Compilation Instructions
1. Ensure you have Kotlin installed.
2. Compile the Kotlin client:
   ```bash
   kotlinc clients/kotlin/sock-client.kt -include-runtime -d sock-client.jar
   ```
3. Run the client:
   ```bash
   java -jar sock-client.jar
   ```

## JavaScript Client

### Description
The JavaScript client uses Node.js to connect to the secure socket server, sending and receiving encrypted messages.

### Compilation Instructions
1. Ensure you have Node.js installed.
2. Install the required packages:
   ```bash
   npm install
   ```
3. Run the client:
   ```bash
   node clients/javascript/sock-client.js
   ```

## C Client

### Description
The C client connects to the server using sockets and implements encryption and HMAC for secure communication.

### Compilation Instructions
1. Ensure you have GCC and OpenSSL installed.
2. Compile the C client:
   ```bash
   gcc -o sock-client clients/c/sock-client.c -lssl -lcrypto
   ```
3. Run the client:
   ```bash
   ./sock-client
   ```

## C++ Client

### Description
The C++ client is similar to the C client but utilizes C++ features for better structure and readability.

### Compilation Instructions
1. Ensure you have g++ and OpenSSL installed.
2. Compile the C++ client:
   ```bash
   g++ -o sock-client clients/c++/sock-client.cpp -lssl -lcrypto
   ```
3. Run the client:
   ```bash
   ./sock-client
   ```

## Rust Client

### Description
The Rust client connects to the server using TCP and implements secure messaging with encryption and HMAC.

### Compilation Instructions
1. Ensure you have Rust installed.
2. Compile the Rust client:
   ```bash
   rustc clients/rust/sock-client.r
   ```
3. Run the client:
   ```bash
   ./sock-client
   ```

## PHP Server

### Description
The PHP server listens for incoming connections and handles secure communication with clients using TLS.

### Compilation Instructions
1. Ensure you have PHP installed with OpenSSL support.
2. Run the PHP server:
   ```bash
   php server/php/sock-server.php
   ```

## License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.
