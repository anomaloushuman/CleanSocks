# CleanSocks

An open-source, cross-platform, secure, extensible, full-duplex custom protocol socket server and client library.

## Table of Contents

- [Java Client](#java-client)
- [Kotlin Client](#kotlin-client)
- [JavaScript Client](#javascript-client)
- [C Client](#c-client)
- [C++ Client](#cpp-client)
- [Rust Client](#rust-client)
- [PHP Server](#php-server)
- [Node.js Server](#nodejs-server)
- [Next.js Server](#nextjs-server)
- [C Server](#c-server)
- [C++ Server](#cpp-server)
- [License](#license)

## Java Client

### Description
The Java client connects to a secure socket server using a custom protocol. It performs a handshake and sends encrypted messages with HMAC for integrity.

### Build Instructions
1. Ensure you have JDK installed.
2. Compile the Java client:
   ```bash
   javac -cp . clients/java/sock-client.java
   ```
3. Run the client:
   ```bash
   java -cp . SecureClient
   ```

### Deployment
- Ensure the server is running and accessible at the specified address and port.

## Kotlin Client

### Description
The Kotlin client functions similarly to the Java client, utilizing Kotlin's features for a more concise implementation.

### Build Instructions
1. Ensure you have Kotlin installed.
2. Compile the Kotlin client:
   ```bash
   kotlinc clients/kotlin/sock-client.kt -include-runtime -d sock-client.jar
   ```
3. Run the client:
   ```bash
   java -jar sock-client.jar
   ```

### Deployment
- Ensure the server is running and accessible at the specified address and port.

## JavaScript Client

### Description
The JavaScript client uses Node.js to connect to the secure socket server, sending and receiving encrypted messages.

### Build Instructions
1. Ensure you have Node.js installed.
2. Install the required packages:
   ```bash
   npm install
   ```
3. Run the client:
   ```bash
   node clients/javascript/sock-client.js
   ```

### Deployment
- Ensure the server is running and accessible at the specified address and port.

## C Client

### Description
The C client connects to the server using sockets and implements encryption and HMAC for secure communication.

### Build Instructions
1. Ensure you have GCC and OpenSSL installed.
2. Compile the C client:
   ```bash
   gcc -o sock-client clients/c/sock-client.c -lssl -lcrypto
   ```
3. Run the client:
   ```bash
   ./sock-client
   ```

### Deployment
- Ensure the server is running and accessible at the specified address and port.

## C++ Client

### Description
The C++ client is similar to the C client but utilizes C++ features for better structure and readability.

### Build Instructions
1. Ensure you have g++ and OpenSSL installed.
2. Compile the C++ client:
   ```bash
   g++ -o sock-client clients/c++/sock-client.cpp -lssl -lcrypto
   ```
3. Run the client:
   ```bash
   ./sock-client
   ```

### Deployment
- Ensure the server is running and accessible at the specified address and port.

## Rust Client

### Description
The Rust client connects to the server using TCP and implements secure messaging with encryption and HMAC.

### Build Instructions
1. Ensure you have Rust installed.
2. Compile the Rust client:
   ```bash
   rustc clients/rust/sock-client.r
   ```
3. Run the client:
   ```bash
   ./sock-client
   ```

### Deployment
- Ensure the server is running and accessible at the specified address and port.

## PHP Server

### Description
The PHP server listens for incoming connections and handles secure communication with clients using TLS.

### Build Instructions
1. Ensure you have PHP installed with OpenSSL support.
2. Run the PHP server:
   ```bash
   php server/php/sock-server.php
   ```

### Deployment
- Ensure the server is configured with the correct paths to the SSL certificates and is running on the specified port.

## Node.js Server

### Description
The Node.js server uses TLS to secure communication with clients.

### Build Instructions
1. Ensure you have Node.js installed.
2. Run the Node.js server:
   ```bash
   node server/node.js/sock-server.node.js
   ```

### Deployment
- Ensure the server is configured with the correct paths to the SSL certificates and is running on the specified port.

## Next.js Server

### Description
The Next.js server uses TLS to secure communication with clients.

### Build Instructions
1. Ensure you have Node.js installed.
2. Run the Next.js server:
   ```bash
   node server/next.js/sock-server.next.js
   ```

### Deployment
- Ensure the server is configured with the correct paths to the SSL certificates and is running on the specified port.

## C Server

### Description
The C server listens for incoming connections and implements secure communication with clients using OpenSSL.

### Build Instructions
1. Ensure you have GCC and OpenSSL installed.
2. Compile the C server:
   ```bash
   gcc -o sock-server server/c/sock-server.c -lssl -lcrypto
   ```
3. Run the server:
   ```bash
   ./sock-server
   ```

### Deployment
- Ensure the server is configured with the correct paths to the SSL certificates and is running on the specified port.

## C++ Server

### Description
The C++ server is similar to the C server but utilizes C++ features for better structure and readability.

### Build Instructions
1. Ensure you have g++ and OpenSSL installed.
2. Compile the C++ server:
   ```bash
   g++ -o sock-server server/c++/sock-server.cpp -lssl -lcrypto
   ```
3. Run the server:
   ```bash
   ./sock-server
   ```

### Deployment
- Ensure the server is configured with the correct paths to the SSL certificates and is running on the specified port.

## License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.
