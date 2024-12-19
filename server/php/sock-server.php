<?php
// Created by anomaloushuman - Patrick Garcia
// 12/19/2024 - Sock Server v0.0.1

$serverKey = 'your-very-secure-key'; // Shared secret key for HMAC and encryption

// TLS context
$context = stream_context_create([
    'ssl' => [
        'local_cert'        => '/path/to/server_cert.pem',
        'local_pk'          => '/path/to/server_key.pem',
        'allow_self_signed' => false,
        'verify_peer'       => true,
        'cafile'            => '/path/to/ca_cert.pem',
    ]
]);

$server = stream_socket_server("tls://0.0.0.0:9000", $errNo, $errStr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);

if (!$server) {
    die("Error: $errStr ($errNo)\n");
}

echo "Secure protocol server started on port 9000\n";

while ($conn = @stream_socket_accept($server)) {
    echo "Client connected\n";

    // Handshake
    fwrite($conn, "HELLO CLIENT\r\n");
    $response = trim(fread($conn, 1024));
    if ($response !== "HELLO SERVER") {
        fwrite($conn, "ERROR: INVALID HANDSHAKE\r\n");
        fclose($conn);
        continue;
    }

    fwrite($conn, "HANDSHAKE COMPLETE\r\n");

    while (!feof($conn)) {
        $data = trim(fread($conn, 2048));
        [$hmac, $encryptedMessage] = explode(":", $data, 2);

        // Verify HMAC
        if (!verifyHmac($encryptedMessage, $hmac, $serverKey)) {
            fwrite($conn, "ERROR: INVALID MESSAGE\r\n");
            break;
        }

        // Decrypt the message
        $message = decryptMessage($encryptedMessage, $serverKey);
        echo "Received: $message\n";

        $response = "You sent: $message";
        $encryptedResponse = encryptMessage($response, $serverKey);
        $hmac = generateHmac($encryptedResponse, $serverKey);

        fwrite($conn, "$hmac:$encryptedResponse\r\n");
    }

    fclose($conn);
    echo "Client disconnected\n";
}

function encryptMessage($message, $key) {
    $iv = random_bytes(16);
    $encrypted = openssl_encrypt($message, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $encrypted);
}

function decryptMessage($data, $key) {
    $data = base64_decode($data);
    $iv = substr($data, 0, 16);
    $encrypted = substr($data, 16);
    return openssl_decrypt($encrypted, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
}

function generateHmac($data, $key) {
    return hash_hmac('sha256', $data, $key);
}

function verifyHmac($data, $hmac, $key) {
    return hash_equals($hmac, hash_hmac('sha256', $data, $key));
}

?>