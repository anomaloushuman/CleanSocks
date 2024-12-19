// Created by anomaloushuman - Patrick Garcia
// Email - patrick@ubiquityglass.com
// 12/19/2024 - Sock Server v0.0.1

import Foundation
import CryptoKit

class SecureClient {
    private let serverAddress = "localhost"
    private let serverPort: UInt32 = 9000
    private let sharedKey = "your-very-secure-key"

    private var inputStream: InputStream?
    private var outputStream: OutputStream?

    func connect() {
        var readStream: Unmanaged<CFReadStream>?
        var writeStream: Unmanaged<CFWriteStream>?

        CFStreamCreatePairWithSocketToHost(nil, serverAddress as CFString, serverPort, &readStream, &writeStream)

        inputStream = readStream?.takeRetainedValue()
        outputStream = writeStream?.takeRetainedValue()

        inputStream?.delegate = self
        outputStream?.delegate = self

        inputStream?.schedule(in: .current, forMode: .default)
        outputStream?.schedule(in: .current, forMode: .default)

        inputStream?.open()
        outputStream?.open()

        handshake()
    }

    private func handshake() {
        guard let outputStream = outputStream else { return }
        let handshakeMessage = "HELLO SERVER\r\n"
        send(message: handshakeMessage)
    }

    func send(message: String) {
        guard let outputStream = outputStream else { return }

        let encryptedMessage = encryptMessage(message)
        let hmac = generateHMAC(for: encryptedMessage)
        let payload = "\(hmac):\(encryptedMessage)\r\n"

        let data = Data(payload.utf8)
        _ = data.withUnsafeBytes {
            outputStream.write($0.bindMemory(to: UInt8.self).baseAddress!, maxLength: data.count)
        }
    }

    private func encryptMessage(_ message: String) -> String {
        let key = SymmetricKey(data: sharedKey.data(using: .utf8)!)
        let iv = AES.GCM.Nonce()
        let sealedBox = try! AES.GCM.seal(message.data(using: .utf8)!, using: key, nonce: iv)
        return (iv + sealedBox.ciphertext).base64EncodedString()
    }

    private func generateHMAC(for message: String) -> String {
        let key = SymmetricKey(data: sharedKey.data(using: .utf8)!)
        let hmac = HMAC<SHA256>.authenticationCode(for: message.data(using: .utf8)!, using: key)
        return Data(hmac).base64EncodedString()
    }

    private func decryptMessage(_ message: String) -> String {
        let key = SymmetricKey(data: sharedKey.data(using: .utf8)!)
        let data = Data(base64Encoded: message)!
        let iv = AES.GCM.Nonce(data.prefix(12))!
        let ciphertext = data.dropFirst(12)
        let sealedBox = try! AES.GCM.SealedBox(nonce: iv, ciphertext: ciphertext, tag: Data())
        return String(data: try! AES.GCM.open(sealedBox, using: key), encoding: .utf8)!
    }
}

extension SecureClient: StreamDelegate {
    func stream(_ aStream: Stream, handle eventCode: Stream.Event) {
        switch eventCode {
        case .hasBytesAvailable:
            guard let inputStream = inputStream else { return }
            var buffer = [UInt8](repeating: 0, count: 1024)
            let bytesRead = inputStream.read(&buffer, maxLength: buffer.count)
            if bytesRead > 0 {
                if let response = String(bytes: buffer, encoding: .utf8) {
                    print("Received: \(response)")
                }
            }
        case .errorOccurred:
            print("Stream error")
        case .endEncountered:
            print("Stream closed")
        default:
            break
        }
    }
}
