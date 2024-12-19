// Created by anomaloushuman - Patrick Garcia
// Email - patrick@ubiquityglass.com
// 12/19/2024 - Sock Server v0.0.1

const net = require("net");
const crypto = require("crypto");

const sharedKey = "your-very-secure-key";

const client = new net.Socket();

function encryptMessage(message) {
    const iv = crypto.randomBytes(16);
    const key = crypto.createHash("sha256").update(sharedKey).digest();
    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
    let encrypted = cipher.update(message, "utf8", "base64");
    encrypted += cipher.final("base64");
    return `${iv.toString("base64")}:${encrypted}`;
}

function generateHMAC(message) {
    const hmac = crypto.createHmac("sha256", sharedKey);
    hmac.update(message);
    return hmac.digest("base64");
}

client.connect(9000, "localhost", () => {
    console.log("Connected to server");
    const handshakeMessage = "HELLO SERVER";
    sendMessage(handshakeMessage);
});

client.on("data", (data) => {
    console.log("Received: " + data.toString());
});

client.on("close", () => {
    console.log("Connection closed");
});

client.on("error", (err) => {
    console.error("Connection error: ", err);
});

function sendMessage(message) {
    const encryptedMessage = encryptMessage(message);
    const hmac = generateHMAC(encryptedMessage);
    const payload = `${hmac}:${encryptedMessage}`;
    client.write(payload + "\r\n");
}
