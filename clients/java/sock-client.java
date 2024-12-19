// Created by anomaloushuman - Patrick Garcia
// Email - patrick@ubiquityglass.com
// 12/19/2024 - Sock Server v0.0.1

import java.io.*;
import java.net.*;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import android.util.Base64;

public class SecureClient {
    private static final String SHARED_KEY = "your-very-secure-key";
    private Socket socket;
    private OutputStream outputStream;
    private InputStream inputStream;

    public SecureClient() {
        try {
            socket = new Socket("localhost", 9000);
            outputStream = socket.getOutputStream();
            inputStream = socket.getInputStream();
            handshake();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void handshake() {
        sendMessage("HELLO SERVER");
        String response = readMessage();
        if (response.equals("HANDSHAKE COMPLETE")) {
            System.out.println("Connected to server!");
        } else {
            System.out.println("Handshake failed: " + response);
        }
    }

    public void sendMessage(String message) {
        String encryptedMessage = encryptMessage(message);
        String hmac = generateHMAC(encryptedMessage);
        String payload = hmac + ":" + encryptedMessage + "\n";
        try {
            outputStream.write(payload.getBytes("UTF-8"));
            outputStream.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String readMessage() {
        try {
            byte[] buffer = new byte[1024];
            int bytesRead = inputStream.read(buffer);
            return new String(buffer, 0, bytesRead, "UTF-8").trim();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    private String encryptMessage(String message) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(SHARED_KEY.getBytes("UTF-8"), "AES");
            byte[] iv = new byte[16];
            new java.util.Random().nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] encryptedData = cipher.doFinal(message.getBytes("UTF-8"));
            return Base64.encodeToString(new byte[][]{iv, encryptedData}, Base64.NO_WRAP);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private String generateHMAC(String message) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(SHARED_KEY.getBytes("UTF-8"), "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKey);
            return Base64.encodeToString(mac.doFinal(message.getBytes("UTF-8")), Base64.NO_WRAP);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        new SecureClient();
    }
}
