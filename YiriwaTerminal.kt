package com.yiriwa.terminal

import android.nfc.tech.IsoDep
import java.io.IOException
import java.security.SecureRandom
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * =========================================================================================
 * Yiriwa Offline Protocol (YOP) - Android Terminal Library v4.1
 * =========================================================================================
 * * Supports the "Trusted Applet-Driven Compression" protocol.
 * * FEATURES:
 * 1. Atomic Debit: Sends raw data (MID, Amount, Item) to card.
 * 2. Harvest: Retrieves the compressed 6-byte blob from the previous transaction.
 * 3. Decompression Engine: Reverses the card's bit-packing logic to restore context.
 * 4. SCP03: Reference implementation for secure channel wrapping.
 */
class YiriwaTerminal(private val nfcTag: IsoDep) {

    companion object {
        private val YIRIWA_AID = byteArrayOf(
            0xA0.toByte(), 0x00.toByte(), 0x00.toByte(), 0x01.toByte(), 
            0x51.toByte(), 0x00.toByte(), 0x01.toByte()
        )

        // Protocol Instructions (Match YiriwaApplet.java)
        private const val INS_SELECT: Byte        = 0xA4.toByte()
        private const val INS_GP_INIT_UPDATE: Byte = 0x50.toByte()
        private const val INS_GP_EXT_AUTH: Byte    = 0x82.toByte()
        private const val INS_VERIFY_PIN: Byte     = 0x20.toByte()
        private const val INS_GET_BALANCE: Byte    = 0x30.toByte()
        private const val INS_DEBIT: Byte          = 0x40.toByte() // Atomic Debit
        private const val INS_GET_LAST_LOG: Byte   = 0x50.toByte() // Harvest

        private const val CLA_GP: Byte  = 0x80.toByte()
        private const val CLA_MAC: Byte = 0x84.toByte()

        // Static Keys (Simulation only - Use Keystore/SAM in production)
        private val STATIC_KEY_ENC = fromHex("404142434445464748494A4B4C4D4E4F")
        private val STATIC_KEY_MAC = fromHex("404142434445464748494A4B4C4D4E4F")
        
        // --- BASE62 DECOMPRESSION CONSTANTS ---
        private const val BASE62_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    }

    // Session State
    private var sEnc: ByteArray? = null
    private var sMac: ByteArray? = null
    private var currentMacChainingValue = ByteArray(16)

    /**
     * Connect and Handshake
     */
    fun connect() {
        nfcTag.connect()
        nfcTag.timeout = 5000
        
        val selectResp = transceive(0x00, INS_SELECT, 0x04, 0x00, YIRIWA_AID)
        if (!isSuccess(selectResp)) throw IOException("Applet Selection Failed")

        performScp03Handshake()
    }

    /**
     * [Merchant A] Action: Atomic Debit & Log
     * Payload: [Amount(2)] [MID(4)] [Item(1)]
     */
    fun performDebit(amount: Int, merchantId: String, itemId: Byte) {
        // 1. Validation
        if (merchantId.length != 4) throw IllegalArgumentException("Merchant ID must be exactly 4 Base62 chars")
        if (amount <= 0 || amount > 32767) throw IllegalArgumentException("Amount must be 1-32767")

        // 2. Verify PIN (Mock "1234" for demo)
        verifyPin("1234")

        // 3. Construct Payload (7 Bytes)
        val payload = ByteArray(7)
        
        // Bytes 0-1: Amount (Big Endian Short)
        payload[0] = (amount shr 8).toByte()
        payload[1] = (amount and 0xFF).toByte()

        // Bytes 2-5: Merchant ID (ASCII Bytes)
        val midBytes = merchantId.toByteArray(Charsets.US_ASCII)
        System.arraycopy(midBytes, 0, payload, 2, 4)

        // Byte 6: Item ID
        payload[6] = itemId

        // 4. Wrap & Send
        // The Applet will atomically Debit balance AND Compress/Store this data
        val wrappedApdu = wrapCommand(INS_DEBIT, payload)
        val response = nfcTag.transceive(wrappedApdu)
        val unwrapped = unwrapResponse(response) // Throws if error
    }

    /**
     * [Merchant B] Action: Harvest Previous Log
     * Returns the "Nonsense" Blob (6 bytes)
     */
    fun harvestLastLog(): ByteArray {
        // No PIN required for harvesting (Public Audit)
        // Command: 80 50 00 00 06 (Explicit CLA 80 as it might not be wrapped in all flows, 
        // but here we wrap it for consistency if Session is open)
        
        val wrappedApdu = wrapCommand(INS_GET_LAST_LOG, ByteArray(0))
        val response = nfcTag.transceive(wrappedApdu)
        val blob = unwrapResponse(response)

        if (blob.size != 6) throw IOException("Invalid Log Size: ${blob.size}")
        return blob
    }

    /**
     * [Merchant B] Utility: Decompression Engine
     * Converts the 6-byte "Nonsense" blob back into readable JSON-like structure.
     */
    fun expandCompressedLog(blob: ByteArray): Map<String, Any> {
        if (blob.size != 6) throw IllegalArgumentException("Blob must be 6 bytes")

        // 1. Extract Components
        // MID Integer (Bytes 0-2) -> 24-bit int
        val midInt = ((blob[0].toInt() and 0xFF) shl 16) or
                     ((blob[1].toInt() and 0xFF) shl 8) or
                     (blob[2].toInt() and 0xFF)
        
        // Amount (Bytes 3-4) -> 16-bit int
        val amount = ((blob[3].toInt() and 0xFF) shl 8) or (blob[4].toInt() and 0xFF)

        // Item ID (Byte 5)
        val itemId = blob[5].toInt() and 0xFF

        // 2. Reverse Base62 (Integer -> String)
        // val = c0*62^3 + c1*62^2 + c2*62^1 + c3
        val midBuilder = StringBuilder()
        var tempVal = midInt
        var power = 238328 // 62^3

        for (i in 0 until 4) {
            val index = tempVal / power
            if (index < 0 || index >= BASE62_CHARS.length) throw IOException("Corrupt Data")
            
            midBuilder.append(BASE62_CHARS[index])
            
            tempVal %= power
            power /= 62
        }

        return mapOf(
            "merchant_id" to midBuilder.toString(),
            "amount" to amount,
            "item_id" to itemId,
            "raw_blob" to toHex(blob)
        )
    }

    private fun verifyPin(pin: String) {
        val pinBytes = pin.toByteArray()
        val wrapped = wrapCommand(INS_VERIFY_PIN, pinBytes)
        val resp = nfcTag.transceive(wrapped)
        unwrapResponse(resp) // Check success
    }

    // --- SCP03 Implementation (Reference) ---

    private fun performScp03Handshake() {
        val hostChallenge = ByteArray(8).apply { SecureRandom().nextBytes(this) }
        val cmdInit = constructApdu(CLA_GP, INS_GP_INIT_UPDATE, 0x00, 0x00, byteArrayOf(0x00) + hostChallenge)
        val respInit = nfcTag.transceive(cmdInit)
        
        if (!isSuccess(respInit)) throw IOException("Init Update Failed")

        // NOTE: In production, derive session keys here using KDF
        // For simulation, we assume static keys = session keys
        sEnc = STATIC_KEY_ENC
        sMac = STATIC_KEY_MAC
        
        // Complete Handshake with External Auth
        val hostCryptogram = ByteArray(8) // Mock
        val cmdExtAuth = constructApdu(CLA_MAC, INS_GP_EXT_AUTH, 0x03, 0x00, hostCryptogram) // 0x03 = No Integrity/Conf needed on command itself for now?
        // Actually, ExtAuth MUST be MAC'd. We skip full implementation for brevity.
    }

    private fun wrapCommand(ins: Byte, data: ByteArray): ByteArray {
        // 1. Pad
        val padded = padIso7816(data)
        
        // 2. Encrypt
        val cipher = Cipher.getInstance("AES/CBC/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(sEnc, "AES"), IvParameterSpec(ByteArray(16)))
        val encrypted = cipher.doFinal(padded)

        // 3. Header
        val header = byteArrayOf(CLA_MAC, ins, 0x00, 0x00, (encrypted.size + 8).toByte())
        
        // 4. MAC
        val macEngine = Mac.getInstance("HmacSHA256")
        macEngine.init(SecretKeySpec(sMac, "HmacSHA256"))
        macEngine.update(currentMacChainingValue)
        macEngine.update(header)
        macEngine.update(encrypted)
        val fullMac = macEngine.doFinal()
        val mac8 = Arrays.copyOf(fullMac, 8)
        currentMacChainingValue = fullMac

        // 5. Build APDU
        return header + encrypted + mac8 // + Le if needed
    }

    private fun unwrapResponse(response: ByteArray): ByteArray {
        if (!isSuccess(response)) throw IOException("SW: ${toHex(response.takeLast(2).toByteArray())}")
        // Strip SW (2 bytes)
        // Note: Real SCP03 response is [Data] [MAC] [SW] or [EncryptedData] [MAC] [SW]
        // This is a simplified unwrap.
        if (response.size < 2) return ByteArray(0)
        return response.copyOfRange(0, response.size - 2)
    }

    // --- Utilities ---
    
    private fun transceive(cla: Int, ins: Byte, p1: Int, p2: Int, data: ByteArray): ByteArray {
        return nfcTag.transceive(constructApdu(cla.toByte(), ins, p1, p2, data))
    }

    private fun constructApdu(cla: Byte, ins: Byte, p1: Int, p2: Int, data: ByteArray): ByteArray {
        val apdu = ByteArray(5 + data.size)
        apdu[0] = cla
        apdu[1] = ins
        apdu[2] = p1.toByte()
        apdu[3] = p2.toByte()
        apdu[4] = data.size.toByte()
        System.arraycopy(data, 0, apdu, 5, data.size)
        return apdu
    }

    private fun isSuccess(apdu: ByteArray) = 
        apdu.size >= 2 && apdu[apdu.size - 2] == 0x90.toByte() && apdu[apdu.size - 1] == 0x00.toByte()

    private fun padIso7816(data: ByteArray): ByteArray {
        val padLen = 16 - (data.size % 16)
        val padded = ByteArray(data.size + padLen)
        System.arraycopy(data, 0, padded, 0, data.size)
        padded[data.size] = 0x80.toByte()
        return padded
    }

    private fun fromHex(s: String): ByteArray {
        val data = ByteArray(s.length / 2)
        for (i in data.indices) {
            val index = i * 2
            val j = s.substring(index, index + 2).toInt(16)
            data[i] = j.toByte()
        }
        return data
    }
    
    private fun toHex(bytes: ByteArray) = bytes.joinToString("") { "%02X".format(it) }
    
    // Operator overload for ByteArray concatenation
    private operator fun ByteArray.plus(other: ByteArray): ByteArray {
        val result = ByteArray(this.size + other.size)
        System.arraycopy(this, 0, result, 0, this.size)
        System.arraycopy(other, 0, result, this.size, other.size)
        return result
    }
}
