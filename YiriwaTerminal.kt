package com.yiriwa.terminal

import android.nfc.tech.IsoDep
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.util.Arrays

/**
 * =========================================================================================
 * Yiriwa Android Terminal v6.0
 * =========================================================================================
 * * UPDATED PROTOCOL (Debit & Swap with Harvesting):
 * 1. Terminal indicates connectivity status (Online/Offline) via P1.
 * 2. Card returns ENTIRE audit history (Variable Length Blob).
 * 3. Terminal handles "SYNC REQUIRED" warning if card is full offline.
 * 4. Terminal passes the harvested blob to the cloud (if online).
 */
class YiriwaTerminal(private val nfcTag: IsoDep) {

    companion object {
        // AID matching the applet
        private val YIRIWA_AID = byteArrayOf(
            0xA0.toByte(), 0x00.toByte(), 0x00.toByte(), 0x01.toByte(), 
            0x51.toByte(), 0x00.toByte(), 0x01.toByte()
        )

        private const val INS_SELECT: Byte         = 0xA4.toByte()
        private const val INS_DEBIT_AND_SWAP: Byte = 0x40.toByte()
        
        // P1 Constants for v6 Applet
        private const val P1_OFFLINE: Byte = 0x00
        private const val P1_ONLINE: Byte  = 0x01
        
        // "SYNC REQUIRED" ASCII bytes
        private val SYNC_MSG_BYTES = "SYNC REQUIRED".toByteArray(StandardCharsets.US_ASCII)
    }

    // Session State
    private var sEnc: ByteArray? = null
    private var sMac: ByteArray? = null

    fun connect() {
        nfcTag.connect()
        nfcTag.timeout = 5000 // Extended timeout for larger data transfer
        
        val selectResp = transceive(0x00, INS_SELECT, 0x04, 0x00, YIRIWA_AID)
        if (!isSuccess(selectResp)) throw IOException("Selection Failed")
        
        // Perform SCP03 Handshake here (omitted)
    }

    /**
     * Perform Debit & Swap (Harvesting)
     * * @param amount Transaction amount (short)
     * @param merchantId 4-character ID
     * @param itemId Item identifier
     * @param isOnline TRUE if the terminal can upload logs immediately (Triggers Card Memory Clear)
     * * @return The Harvested Audit Blob (Variable Size). 
     * @throws IOException If "SYNC REQUIRED" is received or protocol fails.
     */
    fun performDebit(amount: Int, merchantId: String, itemId: Byte, isOnline: Boolean): ByteArray {
        // 1. Validation
        if (merchantId.length != 4) throw IllegalArgumentException("MID must be 4 chars")
        
        // 2. Construct Payload (7 Bytes)
        // [Amount(2)] [MID(4)] [Item(1)]
        val payload = ByteArray(7)
        payload[0] = (amount shr 8).toByte()
        payload[1] = (amount and 0xFF).toByte()
        System.arraycopy(merchantId.toByteArray(StandardCharsets.US_ASCII), 0, payload, 2, 4)
        payload[6] = itemId

        // 3. Determine P1 (Connectivity Status)
        val p1 = if (isOnline) P1_ONLINE else P1_OFFLINE

        // 4. Wrap & Send
        // Note: For large responses, we ensure Le=00 (Max) is handled by the underlying IsoDep/SCP layer.
        val wrappedApdu = wrapCommand(INS_DEBIT_AND_SWAP, p1, payload)
        val response = nfcTag.transceive(wrappedApdu)
        
        // 5. Check for Raw Status Errors first
        // If the card was full and we are offline, it might return 9000 with the text payload, 
        // OR an error code depending on implementation. 
        // Based on v6 Applet code: It returns "SYNC REQUIRED" text + 9000.
        
        // 6. Unwrap & Extract
        val unwrappedData = unwrapResponse(response)

        // 7. Check for "SYNC REQUIRED" Message
        if (Arrays.equals(unwrappedData, SYNC_MSG_BYTES)) {
             throw IOException("TRANSACTION BLOCKED: Card Storage Full. Please find an Online Terminal to sync.")
        }

        // 8. Return the Harvested Blob (List of Logs)
        // This could be 0 bytes (empty) or up to 3600 bytes.
        return unwrappedData
    }

    // --- SCP03 Helper Methods ---

    /**
     * Updated wrapCommand to accept P1
     */
    private fun wrapCommand(ins: Byte, p1: Byte, data: ByteArray): ByteArray {
        // Mock Implementation for SCP03 wrapping
        // Real impl would encrypt 'data' and calculate MAC over Header + EncryptedData
        // Header: [CLA, INS, P1, P2, Lc]
        
        // For this mock, we just prepend the header.
        // CLA=0x84 (Secure), P2=0x00
        val apdu = ByteArray(5 + data.size + 1) // +1 for Le (0x00)
        apdu[0] = 0x84.toByte()
        apdu[1] = ins
        apdu[2] = p1
        apdu[3] = 0x00
        apdu[4] = data.size.toByte()
        System.arraycopy(data, 0, apdu, 5, data.size)
        apdu[apdu.size - 1] = 0x00 // Le = 00 (Expect max response)
        
        return apdu 
    }

    private fun unwrapResponse(response: ByteArray): ByteArray {
        // Mock Implementation
        // Real impl would verify RMAC and decrypt response data
        if (!isSuccess(response)) throw IOException("Card Error: SW=${Integer.toHexString(getSW(response))}")
        
        // Strip SW (last 2 bytes)
        return response.copyOfRange(0, response.size - 2)
    }

    private fun transceive(cla: Int, ins: Byte, p1: Int, p2: Int, data: ByteArray): ByteArray {
        val apdu = ByteArray(5 + data.size)
        apdu[0] = cla.toByte(); apdu[1] = ins; apdu[2] = p1.toByte(); apdu[3] = p2.toByte(); apdu[4] = data.size.toByte()
        System.arraycopy(data, 0, apdu, 5, data.size)
        return nfcTag.transceive(apdu)
    }

    private fun isSuccess(apdu: ByteArray): Boolean {
        if (apdu.size < 2) return false
        val sw1 = apdu[apdu.size - 2]
        val sw2 = apdu[apdu.size - 1]
        return sw1 == 0x90.toByte() && sw2 == 0x00.toByte()
    }
    
    private fun getSW(apdu: ByteArray): Int {
        if (apdu.size < 2) return 0
        return ((apdu[apdu.size - 2].toInt() and 0xFF) shl 8) or (apdu[apdu.size - 1].toInt() and 0xFF)
    }
}
