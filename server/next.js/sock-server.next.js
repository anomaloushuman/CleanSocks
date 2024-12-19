// Created by anomaloushuman - Patrick Garcia
// Email - patrick@ubiquityglass.com
// 12/19/2024 - Sock Server v0.0.1

import tls from 'tls';
import fs from 'fs';
import crypto from 'crypto';

const serverKey = 'your-very-secure-key'; // Shared secret key for HMAC and encryption

const options = {
  key: fs.readFileSync('/path/to/server_key.pem'),
  cert: fs.readFileSync('/path/to/server_cert.pem'),
  ca: fs.readFileSync('/path/to/ca_cert.pem'),
  requestCert: true,
  rejectUnauthorized: true
};

const server = tls.createServer(options, (socket) => {
  console.log('Client connected');

  // Handshake
  socket.write('HELLO CLIENT\r\n');
  socket.on('data', (data) => {
    const response = data.toString().trim();
    if (response !== 'HELLO SERVER') {
      socket.write('ERROR: INVALID HANDSHAKE\r\n');
      socket.end();
      return;
    }

    socket.write('HANDSHAKE COMPLETE\r\n');

    socket.on('data', (data) => {
      const [hmac, encryptedMessage] = data.toString().trim().split(':');

      // Verify HMAC
      if (!verifyHmac(encryptedMessage, hmac, serverKey)) {
        socket.write('ERROR: INVALID MESSAGE\r\n');
        return;
      }

      // Decrypt the message
      const message = decryptMessage(encryptedMessage, serverKey);
      console.log(`Received: ${message}`);

      const response = `You sent: ${message}`;
      const encryptedResponse = encryptMessage(response, serverKey);
      const responseHmac = generateHmac(encryptedResponse, serverKey);

      socket.write(`${responseHmac}:${encryptedResponse}\r\n`);
    });
  });
  socket.on('end', () => {
    console.log('Client disconnected');
  });
});

server.listen(9000, () => {
  console.log('Secure protocol server started on port 9000');
});

function encryptMessage(message, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);
  const encrypted = Buffer.concat([iv, cipher.update(message), cipher.final()]);
  return encrypted.toString('base64');
}

function decryptMessage(data, key) {
  const encrypted = Buffer.from(data, 'base64');
  const iv = encrypted.slice(0, 16);
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key), iv);
  const decrypted = Buffer.concat([decipher.update(encrypted.slice(16)), decipher.final()]);
  return decrypted.toString();
}

function generateHmac(data, key) {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}

function verifyHmac(data, hmac, key) {
  return crypto.timingSafeEqual(Buffer.from(hmac, 'hex'), Buffer.from(generateHmac(data, key), 'hex'));
}