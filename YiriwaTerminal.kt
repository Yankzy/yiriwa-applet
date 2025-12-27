package com.yiriwa.terminal

import android.nfc.tech.IsoDep
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.util.Arrays

/**
 * =========================================================================================
 * Yiriwa Android Terminal v7.0
 * =========================================================================================
 * PROTOCOL OVERVIEW:
 * -----------------------------------------------------------------------------------------
 * This class acts as the interface between the Android App (UI/Logic) and the Java Card.
 * It handles the APDU communication, Secure Channel wrapping (SCP03), and response parsing.
 * * CORE OPERATIONS:
 * 1. DEBIT & HARVEST:
 * - Sends Amount + Merchant ID + Item ID to the card.
 * - Receives a "Harvest Blob" containing: [WalletID (4 bytes)] + [Batch of Logs (N bytes)].
 * - Handles "Online" (Clear Memory) vs "Offline" (Append Memory) flags via P1.
 * * 2. RECHARGE:
 * - Sends Amount to the card via INS_RECHARGE (0x60).
 * - STRICTLY requires SCP03 encryption (handled by wrapCommand).
 * - Returns the new card balance.
 */
class YiriwaTerminal(private val nfcTag: IsoDep) {

    companion object {
        // AID matching the v7 Applet
        private val YIRIWA_AID = byteArrayOf(
            0xA0.toByte(), 0x00.toByte(), 0x00.toByte(), 0x01.toByte(), 
            0x51.toByte(), 0x00.toByte(), 0x01.toByte()
        )

        // --- Instructions ---
        private const val INS_SELECT: Byte         = 0xA4.toByte()
        private const val INS_DEBIT_AND_SWAP: Byte = 0x40.toByte()
        private const val INS_RECHARGE: Byte       = 0x60.toByte() // New in v7

        // --- Constants ---
        private const val P1_OFFLINE: Byte = 0x00
        private const val P1_ONLINE: Byte  = 0x01
        
        // Error Message returned by card if storage is full
        private val SYNC_MSG_BYTES = "SYNC REQUIRED".toByteArray(StandardCharsets.US_ASCII)
    }

    /**
     * Connects to the card and selects the Yiriwa Applet.
     * Note: In a real implementation, perform the SCP03 handshake immediately after selection.
     */
    fun connect() {
        nfcTag.connect()
        nfcTag.timeout = 5000 // Extended timeout for larger log transfers
        
        val selectResp = transceive(0x00, INS_SELECT, 0x04, 0x00, YIRIWA_AID)
        if (!isSuccess(selectResp)) throw IOException("Selection Failed")
        
        // TODO: Perform SCP03 Handshake here (Initialize Update + External Auth)
    }

    /**
     * PERFORMS A TRANSACTION (DEBIT) AND HARVESTS LOGS
     * * @param amount Transaction amount (e.g., 500 for $5.00)
     * @param merchantId 4-character ID of this terminal/merchant
     * @param itemId Unique ID of the item being purchased
     * @param isOnline TRUE if this terminal can sync to blockchain (clears card memory).
     * FALSE if offline (card will append log to history).
     * * @return Pair<String, ByteArray>:
     * - First: Wallet ID (Hex String) identifying the user.
     * - Second: The Harvested Blob (Raw bytes of all offline logs).
     */
    fun performDebit(amount: Int, merchantId: String, itemId: Byte, isOnline: Boolean): Pair<String, ByteArray> {
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

        // 4. Wrap (Encrypt) & Send
        val wrappedApdu = wrapCommand(INS_DEBIT_AND_SWAP, p1, payload)
        val response = nfcTag.transceive(wrappedApdu)
        
        // 5. Unwrap (Decrypt)
        val unwrappedData = unwrapResponse(response)

        // 6. Check for specific "Storage Full" warning
        if (Arrays.equals(unwrappedData, SYNC_MSG_BYTES)) {
             throw IOException("TRANSACTION BLOCKED: Card Storage Full. Please find an Online Terminal.")
        }

        // 7. Parse Identity Header (v7 Protocol)
        // The first 4 bytes are ALWAYS the Wallet ID.
        if (unwrappedData.size < 4) {
             // This might happen if it's the very first transaction on a fresh card 
             // and the applet implementation returns just the ID and 0 logs.
             // If size < 4, it's a protocol violation.
             throw IOException("Invalid Response: Missing Identity Header")
        }

        val walletIdBytes = unwrappedData.copyOfRange(0, 4)
        val logsBlob = unwrappedData.copyOfRange(4, unwrappedData.size)

        return Pair(toHex(walletIdBytes), logsBlob)
    }

    /**
     * PERFORMS A RECHARGE (ADD FUNDS)
     * * @param amount Amount to add to the card balance.
     * @return The new updated balance on the card.
     */
    fun performRecharge(amount: Int): Int {
        if (amount <= 0) throw IllegalArgumentException("Amount must be positive")

        // 1. Construct Payload [Amount(2)]
        val payload = ByteArray(2)
        payload[0] = (amount shr 8).toByte()
        payload[1] = (amount and 0xFF).toByte()

        // 2. Wrap & Send (INS_RECHARGE = 0x60)
        // Critical: The applet enforces SCP for this command.
        val wrappedApdu = wrapCommand(INS_RECHARGE, 0x00, payload)
        val response = nfcTag.transceive(wrappedApdu)
        
        // 3. Unwrap Response
        val unwrappedData = unwrapResponse(response)
        
        // 4. Parse New Balance (2 bytes)
        if (unwrappedData.size != 2) throw IOException("Invalid Recharge Response")
        
        return ((unwrappedData[0].toInt() and 0xFF) shl 8) or (unwrappedData[1].toInt() and 0xFF)
    }

    // --- SCP03 / Crypto Helpers (Mocked for Structure) ---

    /**
     * Wraps an APDU command with SCP03 Encryption & MAC.
     */
    private fun wrapCommand(ins: Byte, p1: Byte, data: ByteArray): ByteArray {
        // Real implementation requires GlobalPlatform SCP logic.
        // We construct a Secure CLA (0x84) APDU.
        val apdu = ByteArray(5 + data.size + 1) // +1 for Le
        apdu[0] = 0x84.toByte() // CLA: GlobalPlatform Secure
        apdu[1] = ins
        apdu[2] = p1
        apdu[3] = 0x00          // P2
        apdu[4] = data.size.toByte()
        System.arraycopy(data, 0, apdu, 5, data.size)
        apdu[apdu.size - 1] = 0x00 // Le = 00 (Expect Max Response)
        
        return apdu 
    }

    /**
     * Unwraps a Secure Response (Verifies RMAC & Decrypts Data).
     */
    private fun unwrapResponse(response: ByteArray): ByteArray {
        val sw = getSW(response)
        
        // Handle specific applet errors
        if (sw == 0x6986) throw IOException("Card Storage Full (SW 6986)")
        if (sw == 0x6987) throw IOException("Balance Limit Reached (SW 6987)")
        if (sw == 0x6301) throw IOException("PIN Verification Required (SW 6301)")
        
        if (!isSuccess(response)) {
            throw IOException("Card Error: SW=${Integer.toHexString(sw)}")
        }
        
        // In a real SCP implementation, we strip the SW and decrypt the body.
        return response.copyOfRange(0, response.size - 2)
    }

    // --- Standard ISO Helpers ---

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
    
    private fun toHex(bytes: ByteArray): String {
        val sb = StringBuilder()
        for (b in bytes) {
            sb.append(String.format("%02X", b))
        }
        return sb.toString()
    }
}
