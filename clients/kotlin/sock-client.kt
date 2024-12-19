// Created by anomaloushuman - Patrick Garcia
// Email - patrick@ubiquityglass.com
// 12/19/2024 - Sock Server v0.0.1

import java.io.*
import java.net.Socket
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import android.util.Base64

class SecureClient(private val serverAddress: String, private val serverPort: Int) {
    private val sharedKey = "your-very-secure-key"
    private var socket: Socket? = null
    private var outputStream: OutputStream? = null
    private var inputStream: InputStream? = null

    fun connect() {
        socket = Socket(serverAddress, serverPort)
        outputStream = socket?.getOutputStream()
        inputStream = socket?.getInputStream()

        handshake()
    }

    private fun handshake() {
        sendMessage("HELLO SERVER")
        val response = readMessage()
        if (response == "HANDSHAKE COMPLETE") {
            println("Connected to server!")
        } else {
            println("Handshake failed: $response")
        }
    }

    fun sendMessage(message: String) {
        val encryptedMessage = encryptMessage(message)
        val hmac = generateHMAC(encryptedMessage)
        val payload = "$hmac:$encryptedMessage\n"
        outputStream?.write(payload.toByteArray(Charsets.UTF_8))
        outputStream?.flush()
    }

    fun readMessage(): String {
        val buffer = ByteArray(1024)
        val bytesRead = inputStream?.read(buffer) ?: 0
        return String(buffer, 0, bytesRead, Charsets.UTF_8).trim()
    }

    private fun encryptMessage(message: String): String {
        val secretKey = SecretKeySpec(sharedKey.toByteArray(Charsets.UTF_8), "AES")
        val iv = ByteArray(16).apply { java.util.Random().nextBytes(this) }
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding").apply {
            init(Cipher.ENCRYPT_MODE, secretKey, IvParameterSpec(iv))
        }
        val encryptedData = iv + cipher.doFinal(message.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(encryptedData, Base64.NO_WRAP)
    }

    private fun decryptMessage(encryptedMessage: String): String {
        val secretKey = SecretKeySpec(sharedKey.toByteArray(Charsets.UTF_8), "AES")
        val decodedData = Base64.decode(encryptedMessage, Base64.NO_WRAP)
        val iv = decodedData.copyOfRange(0, 16)
        val cipherText = decodedData.copyOfRange(16, decodedData.size)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding").apply {
            init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))
        }
        return String(cipher.doFinal(cipherText), Charsets.UTF_8)
    }

    private fun generateHMAC(message: String): String {
        val secretKey = SecretKeySpec(sharedKey.toByteArray(Charsets.UTF_8), "HmacSHA256")
        val mac = Mac.getInstance("HmacSHA256").apply { init(secretKey) }
        return Base64.encodeToString(mac.doFinal(message.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP)
    }
}
