package com.yiriwa.terminal

import android.nfc.tech.IsoDep
import java.io.IOException
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.IvParameterSpec

/**
 * =========================================================================================
 * Yiriwa Android Terminal v5.1
 * =========================================================================================
 * * UPDATED FLOW: "Dumb POS"
 * 1. Sends Atomic Debit Command (Pop-and-Push).
 * 2. Receives Opaque Blob (Previous Audit Log).
 * 3. Returns Blob to App Logic (for upload to Cloud).
 * 4. NO Local Decompression.
 */
class YiriwaTerminal(private val nfcTag: IsoDep) {

    companion object {
        private val YIRIWA_AID = byteArrayOf(
            0xA0.toByte(), 0x00.toByte(), 0x00.toByte(), 0x01.toByte(), 
            0x51.toByte(), 0x00.toByte(), 0x01.toByte()
        )

        private const val INS_SELECT: Byte         = 0xA4.toByte()
        private const val INS_DEBIT_AND_SWAP: Byte = 0x40.toByte() // v5.1 Instruction
        
        // ... SCP Constants omitted for brevity (same as before) ...
    }

    // Session State
    private var sEnc: ByteArray? = null
    private var sMac: ByteArray? = null

    fun connect() {
        nfcTag.connect()
        nfcTag.timeout = 5000
        val selectResp = transceive(0x00, INS_SELECT, 0x04, 0x00, YIRIWA_AID)
        if (!isSuccess(selectResp)) throw IOException("Selection Failed")
        // Perform SCP03 Handshake here (omitted for brevity)
        // Assume sEnc/sMac are set
    }

    /**
     * Perform Debit & Swap
     * Returns: The *Previous* Audit Log Blob (10 bytes) found on the card.
     */
    fun performDebit(amount: Int, merchantId: String, itemId: Byte): ByteArray {
        // 1. Validation
        if (merchantId.length != 4) throw IllegalArgumentException("MID must be 4 chars")
        
        // 2. Construct Payload (7 Bytes)
        // [Amount(2)] [MID(4)] [Item(1)]
        val payload = ByteArray(7)
        payload[0] = (amount shr 8).toByte()
        payload[1] = (amount and 0xFF).toByte()
        System.arraycopy(merchantId.toByteArray(Charsets.US_ASCII), 0, payload, 2, 4)
        payload[6] = itemId

        // 3. Wrap & Send (INS_DEBIT_AND_SWAP)
        // Note: Applet v5.1 requires SCP Wrapping
        val wrappedApdu = wrapCommand(INS_DEBIT_AND_SWAP, payload)
        val response = nfcTag.transceive(wrappedApdu)
        
        // 4. Unwrap & Extract
        val unwrappedData = unwrapResponse(response)

        // 5. Return the Harvested Blob
        // The Applet returns exactly 10 bytes: [Old_Data(6)] [Old_MAC(4)]
        if (unwrappedData.size != 10) {
            // It might be 0 if card was empty/genesis, but v5.1 applet returns 10 bytes of init data usually
            if (unwrappedData.isEmpty()) return ByteArray(10) // Return empty zeros
            throw IOException("Protocol Mismatch: Expected 10 bytes returned, got ${unwrappedData.size}")
        }

        return unwrappedData
    }

    // --- Removed expandCompressedLog() ---
    // The POS is now explicitly "dumb" regarding the blob content.

    // ... SCP03 wrap/unwrap logic same as previous version ...
    
    private fun wrapCommand(ins: Byte, data: ByteArray): ByteArray {
        // Mock Implementation for structure
        return byteArrayOf(0x84.toByte(), ins, 0x00, 0x00, data.size.toByte()) + data 
    }

    private fun unwrapResponse(response: ByteArray): ByteArray {
        // Mock Implementation
        if (!isSuccess(response)) throw IOException("Card Error")
        return response.copyOfRange(0, response.size - 2)
    }

    private fun transceive(cla: Int, ins: Byte, p1: Int, p2: Int, data: ByteArray): ByteArray {
        val apdu = ByteArray(5 + data.size)
        apdu[0] = cla.toByte(); apdu[1] = ins; apdu[2] = p1.toByte(); apdu[3] = p2.toByte(); apdu[4] = data.size.toByte()
        System.arraycopy(data, 0, apdu, 5, data.size)
        return nfcTag.transceive(apdu)
    }

    private fun isSuccess(apdu: ByteArray) = 
        apdu.size >= 2 && apdu[apdu.size - 2] == 0x90.toByte() && apdu[apdu.size - 1] == 0x00.toByte()
        
    private operator fun ByteArray.plus(other: ByteArray): ByteArray {
        val result = ByteArray(this.size + other.size)
        System.arraycopy(this, 0, result, 0, this.size)
        System.arraycopy(other, 0, result, this.size, other.size)
        return result
    }
}
