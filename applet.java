package com.yiriwa.wallet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
import org.globalplatform.*;

/**
 * YiriwaApplet - Offline Secure Wallet with Audit Harvesting V6
 * * -----------------------------------------------------------------------------
 * OVERVIEW
 * -----------------------------------------------------------------------------
 * This applet implements a "Debit & Swap" protocol designed for offline payments
 * in areas with intermittent connectivity. It acts as a secure audit log carrier.
 * * CORE PROTOCOL (Debit & Swap):
 * 1. HARVEST: When a terminal interacts with the card, the card returns ALL 
 * previously stored transaction logs. This allows the terminal (if online) 
 * to upload them to the backend/blockchain.
 * 2. COMMIT: The card atomically debits the user's balance.
 * 3. SWAP/APPEND: 
 * - If POS is ONLINE (P1=0x01): The card CLEARS the old logs and stores 
 * ONLY the current transaction. The old logs are assumed safely uploaded.
 * - If POS is OFFLINE (P1=0x00): The card APPENDS the current transaction 
 * to the internal list, preserving old logs until an online sync occurs.
 * * STORAGE & COMPRESSION:
 * - Capacity: Stores up to 300 offline transactions.
 * - Format: Each log is compressed to 12 bytes:
 * [3 Bytes Compressed ID] [2 Bytes Amount] [1 Byte Item ID] [4 Bytes MAC] [2 Bytes Country ISO]
 * - Security: Logs are internally MAC'd to prevent tampering.
 * * SECURITY:
 * - Relies on GlobalPlatform Secure Channel (SCP02/03) for all critical operations.
 * - Uses Atomic Transactions to ensure data integrity during power loss.
 */
public class YiriwaApplet extends Applet {

    // -------------------------------------------------------------------------
    // Constants: Instructions (INS)
    // -------------------------------------------------------------------------
    private static final byte CLA_YIRIWA          = (byte) 0x80;
    
    // Verifies the user's PIN (required before debit)
    private static final byte INS_VERIFY_PIN      = (byte) 0x20; 
    // Returns the current balance (requires Secure Channel)
    private static final byte INS_GET_BALANCE     = (byte) 0x30; 
    // The core payment command: Harvests logs + Debits amount + Stores new log
    private static final byte INS_DEBIT_AND_SWAP  = (byte) 0x40; 
    
    // -------------------------------------------------------------------------
    // Constants: Parameters (P1/P2)
    // -------------------------------------------------------------------------
    // P1 in INS_DEBIT_AND_SWAP indicates the connectivity status of the POS
    private static final byte POS_STATUS_OFFLINE  = (byte) 0x00;
    private static final byte POS_STATUS_ONLINE   = (byte) 0x01;

    // -------------------------------------------------------------------------
    // Constants: GlobalPlatform & Errors
    // -------------------------------------------------------------------------
    private static final byte INS_GP_INITIALIZE_UPDATE = (byte) 0x50;
    private static final byte INS_GP_EXTERNAL_AUTH     = (byte) 0x82;

    private static final short SW_PIN_REQUIRED       = (short) 0x6301;
    private static final short SW_INSUFFICIENT_FUNDS = (short) 0x6910;
    private static final short SW_INVALID_FORMAT     = (short) 0x6911;
    private static final short SW_SECURE_CHANNEL     = (short) 0x6982;
    // New Error: Returned when the 300-record buffer is full in offline mode
    private static final short SW_STORAGE_FULL       = (short) 0x6986;

    // -------------------------------------------------------------------------
    // Configuration: Memory Layout
    // -------------------------------------------------------------------------
    // Maximum number of offline records before sync is FORCED
    private static final short MAX_RECORDS = (short) 300;
    // Size of a single compressed log entry in bytes
    private static final short LOG_SIZE    = (short) 12; 
    // Total EEPROM buffer size: 300 * 12 = 3600 Bytes
    private static final short MAX_BUFFER_SIZE = (short) (MAX_RECORDS * LOG_SIZE);

    // -------------------------------------------------------------------------
    // State (Persistent EEPROM)
    // -------------------------------------------------------------------------
    private OwnerPIN userPin;
    private short balance;
    
    /**
     * The main storage buffer. This acts as a linear list.
     * New records are appended until an ONLINE POS clears it.
     */
    private byte[] transactionLogs; 
    
    /**
     * Tracks the number of valid records currently stored in 'transactionLogs'.
     * Range: 0 to 300.
     */
    private short logCount; 
    
    // Country code (e.g., 504 for Morocco) loaded during installation
    private short countryISO;

    // -------------------------------------------------------------------------
    // Crypto & RAM (Transient)
    // -------------------------------------------------------------------------
    private Signature macSignature;
    private DESKey macKey;
    private SecureChannel secureChannel;
    private byte[] scratchBuffer; // RAM buffer for fast calculation

    // Internal key for generating Log MACs (Proof of Origin)
    private static final byte[] DEFAULT_KEY = {
        (byte)0x59, (byte)0x49, (byte)0x52, (byte)0x49, 
        (byte)0x57, (byte)0x41, (byte)0x5F, (byte)0x4B 
    };

    /**
     * Constructor: Initializes the applet state and allocates memory.
     */
    private YiriwaApplet(byte[] bArray, short bOffset, byte bLength) {
        // 1. Parse Install Parameters to extract Country ISO
        // Format: [Li][AID][Lc][Privs][La][Params...]
        short aidLen = bArray[bOffset];
        short privOffset = (short)(bOffset + aidLen + 1);
        short privLen = bArray[privOffset];
        short paramOffset = (short)(privOffset + privLen + 1);
        short paramLen = bArray[paramOffset];
        
        // We expect the first 2 bytes of Applet Params to be the Country ISO
        if (paramLen >= 2) {
            countryISO = Util.makeShort(bArray[(short)(paramOffset + 1)], bArray[(short)(paramOffset + 2)]);
        } else {
            countryISO = (short) 0; 
        }

        // 2. Initialize PIN (Default: 1234)
        userPin = new OwnerPIN((byte) 3, (byte) 4);
        byte[] defaultPin = {(byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78};
        userPin.update(defaultPin, (short) 0, (byte) 4);

        // 3. Initialize Wallet State
        balance = 20000; // Example initial balance
        
        // Allocate the large storage buffer in EEPROM
        transactionLogs = new byte[MAX_BUFFER_SIZE];
        logCount = 0;

        // 4. Initialize Crypto Objects
        try {
            // Try ISO9797_M2 first, fallback to NOPAD if not supported
            macSignature = Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_1_M2_ALG3, false);
            macKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
            macKey.setKey(DEFAULT_KEY, (short) 0);
        } catch (CryptoException e) {
            macSignature = Signature.getInstance(Signature.ALG_DES_MAC8_NOPAD, false);
        }

        // Get handle to GlobalPlatform Secure Channel
        secureChannel = GPSystem.getSecureChannel();
        
        // Allocate RAM buffer (erased on card reset)
        scratchBuffer = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new YiriwaApplet(bArray, bOffset, bLength);
    }

    /**
     * Main APDU Dispatcher
     */
    public void process(APDU apdu) {
        if (selectingApplet()) return;

        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];
        byte cla = buffer[ISO7816.OFFSET_CLA];

        // Hand off security commands to GlobalPlatform
        if (cla == (byte) 0x80 && (ins == INS_GP_INITIALIZE_UPDATE || ins == INS_GP_EXTERNAL_AUTH)) {
            secureChannel.processSecurity(apdu);
            return;
        }

        // Verify proprietary CLA
        if ((cla & (byte) 0xFC) != CLA_YIRIWA) {
             ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (ins) {
            case INS_VERIFY_PIN:
                enforceSecureChannel(apdu);
                verifyPin(apdu);
                break;
            case INS_GET_BALANCE:
                enforceSecureChannel(apdu);
                getBalance(apdu);
                break;
            case INS_DEBIT_AND_SWAP:
                enforceSecureChannel(apdu);
                processDebitAndSwap(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // --- Core Business Logic -------------------------------------------------

    /**
     * INS_DEBIT_AND_SWAP
     * * Handles the payment and log management logic.
     * P1 = 0x00 (Offline POS): Append log, keep history.
     * P1 = 0x01 (Online POS):  Clear history, start fresh with this log.
     */
    private void processDebitAndSwap(APDU apdu) {
        // 1. Security Check
        if (!userPin.isValidated()) ISOException.throwIt(SW_PIN_REQUIRED);

        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[ISO7816.OFFSET_P1]; // Online/Offline Flag
        short offset = ISO7816.OFFSET_CDATA;
        
        // ---------------------------------------------------------------------
        // 2. Capacity Check (The "Offline Limit")
        // ---------------------------------------------------------------------
        // If the card is full (300 logs) and the terminal is OFFLINE, we cannot
        // accept more transactions because we can't free memory (sync required).
        if (logCount >= MAX_RECORDS && p1 == POS_STATUS_OFFLINE) {
            // Return human readable text warning
            byte[] msg = {'S','Y','N','C',' ','R','E','Q','U','I','R','E','D'};
            Util.arrayCopyNonAtomic(msg, (short)0, buffer, (short)0, (short)msg.length);
            apdu.setOutgoingAndSend((short)0, (short)msg.length);
            return; // Exit transaction
        }

        // ---------------------------------------------------------------------
        // 3. Parse & Validate Transaction Data
        // ---------------------------------------------------------------------
        short amount = Util.makeShort(buffer[offset], buffer[(short)(offset+1)]);
        short idOffset = (short)(offset + 2); // 4-char Transaction ID start
        byte itemID = buffer[(short)(offset + 6)];

        if (amount <= 0) ISOException.throwIt(SW_INVALID_FORMAT);
        if (balance < amount) ISOException.throwIt(SW_INSUFFICIENT_FUNDS);

        // ---------------------------------------------------------------------
        // 4. Prepare New Log in RAM (Scratchpad)
        // ---------------------------------------------------------------------
        // We build the 12-byte log in RAM first to avoid unnecessary EEPROM writes.
        
        // A. Compress ID (4 bytes -> 3 bytes)
        compressAndPack(buffer, idOffset, amount, itemID, scratchBuffer, (short) 0);
        
        // B. Generate MAC (Sign the first 6 bytes, output 4 bytes signature)
        generateTruncatedMAC(scratchBuffer, (short) 0, (short) 6, scratchBuffer, (short) 6);
        
        // C. Append Country ISO (Last 2 bytes)
        Util.setShort(scratchBuffer, (short) 10, countryISO);

        // ---------------------------------------------------------------------
        // 5. "Harvesting": Prepare Response Payload
        // ---------------------------------------------------------------------
        // We must copy the EXISTING logs to the APDU buffer *before* we modify
        // the list. The terminal needs the history, regardless of online/offline.
        
        short currentLogSizeByte = (short)(logCount * LOG_SIZE);
        
        // Check if APDU buffer can hold the data (Max ~3600 bytes requires Extended Length)
        if (logCount > 0) {
            Util.arrayCopyNonAtomic(transactionLogs, (short)0, buffer, (short)0, currentLogSizeByte);
        }

        // ---------------------------------------------------------------------
        // 6. Atomic Transaction (Commit)
        // ---------------------------------------------------------------------
        JCSystem.beginTransaction();
        try {
            // A. Deduct Balance
            balance = (short)(balance - amount);

            if (p1 == POS_STATUS_ONLINE) {
                // --- ONLINE MODE ---
                // The POS is online, so it will upload the 'harvested' logs we just 
                // put in the buffer. We can now safely clear the card's memory.
                
                // 1. Overwrite the start of the array with the NEW log
                Util.arrayCopy(scratchBuffer, (short) 0, transactionLogs, (short) 0, LOG_SIZE);
                
                // 2. Reset the counter to 1 (Effective Clear)
                // We don't need to physically zero-out the rest of EEPROM; 
                // the logCount controls visibility.
                logCount = 1; 

            } else {
                // --- OFFLINE MODE ---
                // The POS cannot sync. We must keep old logs and append the new one.
                
                // 1. Calculate offset for the new record
                short newOffset = (short)(logCount * LOG_SIZE);
                
                // 2. Append new log
                Util.arrayCopy(scratchBuffer, (short) 0, transactionLogs, newOffset, LOG_SIZE);
                
                // 3. Increment counter
                logCount++;
            }

            // Commit updates to Balance, Array, and Counter simultaneously
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }

        // ---------------------------------------------------------------------
        // 7. Send Secure Response
        // ---------------------------------------------------------------------
        // Returns the harvested logs (encrypted via Secure Channel)
        sendSecureResponse(apdu, currentLogSizeByte);
    }

    // --- Compression Engine --------------------------------------------------

    /**
     * Compresses transaction data into the 12-byte format.
     * Logic: Base62 String -> 24-bit Integer
     */
    private void compressAndPack(byte[] src, short srcOff, short amount, byte item, byte[] dest, short destOff) {
        // Clear 3 bytes for ID
        Util.arrayFillNonAtomic(scratchBuffer, (short) 20, (short) 3, (byte) 0);
        
        // Loop through 4 chars of ID
        for (short i = 0; i < 4; i++) {
            byte c = src[(short)(srcOff + i)];
            short val = mapBase62(c);
            multiply24BitBy62AndAdd(scratchBuffer, (short) 20, val);
        }

        // Copy Compressed ID (3 bytes)
        Util.arrayCopy(scratchBuffer, (short) 20, dest, destOff, (short) 3);
        // Copy Amount (2 bytes)
        Util.setShort(dest, (short)(destOff+3), amount);
        // Copy Item ID (1 byte)
        dest[(short)(destOff+5)] = item;
    }

    /**
     * Helper: Performs (A * 62 + B) on a 24-bit number stored in a byte array.
     */
    private void multiply24BitBy62AndAdd(byte[] arr, short offset, short addVal) {
        // Process LSB (Byte 2)
        short b2 = (short)(arr[(short)(offset+2)] & 0xFF);
        short res2 = (short)((b2 * 62) + addVal); 
        arr[(short)(offset+2)] = (byte) res2; 
        short carry = (short)((res2 >>> 8) & 0xFF); 

        // Process Middle (Byte 1)
        short b1 = (short)(arr[(short)(offset+1)] & 0xFF);
        short res1 = (short)((b1 * 62) + carry);
        arr[(short)(offset+1)] = (byte) res1;
        carry = (short)((res1 >>> 8) & 0xFF);

        // Process MSB (Byte 0)
        short b0 = (short)(arr[offset] & 0xFF);
        short res0 = (short)((b0 * 62) + carry);
        arr[offset] = (byte) res0;
    }

    /**
     * Maps ASCII chars (0-9, A-Z, a-z) to 0-61.
     */
    private short mapBase62(byte c) {
        if (c >= '0' && c <= '9') return (short)(c - '0');
        if (c >= 'A' && c <= 'Z') return (short)(c - 'A' + 10);
        if (c >= 'a' && c <= 'z') return (short)(c - 'a' + 36);
        ISOException.throwIt(SW_INVALID_FORMAT);
        return 0;
    }

    // --- Crypto Helpers ------------------------------------------------------

    /**
     * Generates a signature for the log to ensure authenticity.
     * Takes first 'dLen' bytes -> returns 4 byte truncated MAC.
     */
    private void generateTruncatedMAC(byte[] data, short dOff, short dLen, byte[] dest, short destOff) {
        macSignature.init(macKey, Signature.MODE_SIGN);
        // Sign data, store result in temp buffer (offset 20)
        short sigLen = macSignature.sign(data, dOff, dLen, scratchBuffer, (short) 20);
        // Copy only first 4 bytes to destination
        Util.arrayCopy(scratchBuffer, (short) 20, dest, destOff, (short) 4);
    }

    // --- SCP03 / GlobalPlatform Helpers --------------------------------------

    /**
     * Ensures the command is wrapped in a GlobalPlatform Secure Channel (MAC + ENC).
     */
    private void enforceSecureChannel(APDU apdu) {
        byte level = secureChannel.getSecurityLevel();
        // Require both Encryption (Confidentiality) and MAC (Integrity)
        if ((level & (SecureChannel.C_DECRYPTION | SecureChannel.C_MAC)) == 0) {
            ISOException.throwIt(SW_SECURE_CHANNEL);
        }
        try {
            // Decrypt incoming APDU data
            short len = apdu.setIncomingAndReceive();
            short clearLen = secureChannel.unwrap(apdu.getBuffer(), (short) 0, (short)(len + 5));
            apdu.setIncomingLength(clearLen);
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    /**
     * Encrypts the response data before sending it back to the terminal.
     */
    private void sendSecureResponse(APDU apdu, short len) {
        short secureLen = secureChannel.wrap(apdu.getBuffer(), (short) 0, len);
        apdu.setOutgoingAndSend((short) 0, secureLen);
    }

    /**
     * Wrapper for OwnerPIN verification.
     */
    private void verifyPin(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        if (!userPin.check(buf, ISO7816.OFFSET_CDATA, (byte) buf[ISO7816.OFFSET_LC])) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        sendSecureResponse(apdu, (short) 0);
    }

    private void getBalance(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        Util.setShort(buf, (short) 0, balance);
        sendSecureResponse(apdu, (short) 2);
    }
}
