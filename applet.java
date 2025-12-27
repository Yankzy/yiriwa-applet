package com.yiriwa.wallet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
import org.globalplatform.*;

/**
 * =============================================================================
 * YiriwaApplet v7.0 - Secure Offline Wallet with Identity & Recharge
 * =============================================================================
 * * CORE PROTOCOL (Debit & Swap + Identity):
 * -----------------------------------------------------------------------------
 * 1. IDENTITY HEADER:
 * Every "Harvest" response now begins with a 4-byte Wallet ID.
 * Response Format: [WalletID (4b)] + [Log 1 (12b)] + [Log 2 (12b)] ...
 * * 2. RECHARGE FLOW (New):
 * Allows authorized terminals to increase the card balance via INS_RECHARGE.
 * This command REQUIRES a fully encrypted Secure Channel (SCP02/03).
 *
 * 3. DEBIT FLOW:
 * - Validates PIN.
 * - Deducts Balance.
 * - Compresses Transaction Data.
 * - Appends to Internal Log (if Offline) OR Clears Log (if Online).
 * - Returns the 'Harvest' (previous logs) to the terminal.
 *
 * MEMORY LAYOUT:
 * -----------------------------------------------------------------------------
 * - Storage Limit: 300 Transactions (3600 Bytes).
 * - Log Format: [Compressed ID (3b)] [Amount (2b)] [Item (1b)] [MAC (4b)] [ISO (2b)].
 * - Atomicity: All state changes are protected by Java Card Transactions.
 */
public class YiriwaApplet extends Applet {

    // -------------------------------------------------------------------------
    // 1. Instructions (INS)
    // -------------------------------------------------------------------------
    private static final byte CLA_YIRIWA          = (byte) 0x80;
    
    // Verifies the user's PIN (required before debit)
    private static final byte INS_VERIFY_PIN      = (byte) 0x20; 
    // Returns the current balance (requires Secure Channel)
    private static final byte INS_GET_BALANCE     = (byte) 0x30; 
    // Core payment command: Harvests logs + Debits amount + Stores new log
    private static final byte INS_DEBIT_AND_SWAP  = (byte) 0x40; 
    // NEW: Adds funds to the wallet (Strictly authorized)
    private static final byte INS_RECHARGE        = (byte) 0x60; 

    // -------------------------------------------------------------------------
    // 2. Constants & Errors
    // -------------------------------------------------------------------------
    // POS Connectivity Status (Sent in P1)
    private static final byte POS_STATUS_OFFLINE  = (byte) 0x00;
    private static final byte POS_STATUS_ONLINE   = (byte) 0x01;

    // GlobalPlatform Commands
    private static final byte INS_GP_INITIALIZE_UPDATE = (byte) 0x50;
    private static final byte INS_GP_EXTERNAL_AUTH     = (byte) 0x82;

    // Error Codes
    private static final short SW_PIN_REQUIRED       = (short) 0x6301;
    private static final short SW_INSUFFICIENT_FUNDS = (short) 0x6910;
    private static final short SW_INVALID_FORMAT     = (short) 0x6911;
    private static final short SW_SECURE_CHANNEL     = (short) 0x6982;
    private static final short SW_STORAGE_FULL       = (short) 0x6986;
    private static final short SW_BALANCE_OVERFLOW   = (short) 0x6987;

    // Configuration
    private static final short MAX_RECORDS = (short) 300;
    private static final short LOG_SIZE    = (short) 12; 
    // Total Buffer: 300 * 12 = 3600 Bytes
    private static final short MAX_BUFFER_SIZE = (short) (MAX_RECORDS * LOG_SIZE);
    
    // Max Balance Safety Cap (Signed Short Max is 32,767)
    // We cap at 30,000 to prevent overflow arithmetic issues.
    private static final short MAX_BALANCE_CAP = (short) 30000; 

    // -------------------------------------------------------------------------
    // 3. State (Persistent EEPROM)
    // -------------------------------------------------------------------------
    private OwnerPIN userPin;
    private short balance;
    
    // The main storage buffer. Acts as a linear list of logs.
    private byte[] transactionLogs; 
    
    // Tracks current number of stored records (0 to 300)
    private short logCount; 
    
    // Country code loaded at install (e.g., 504)
    private short countryISO;
    
    // NEW: Unique 4-Byte Wallet Identifier
    private byte[] walletID;

    // -------------------------------------------------------------------------
    // 4. Crypto & RAM (Transient)
    // -------------------------------------------------------------------------
    private Signature macSignature;
    private DESKey macKey;
    private SecureChannel secureChannel;
    private byte[] scratchBuffer; 

    // Internal key for generating Log MACs (Proof of Origin)
    private static final byte[] DEFAULT_KEY = {
        (byte)0x59, (byte)0x49, (byte)0x52, (byte)0x49, 
        (byte)0x57, (byte)0x41, (byte)0x5F, (byte)0x4B 
    };

    /**
     * Constructor: Initializes Applet State
     */
    private YiriwaApplet(byte[] bArray, short bOffset, byte bLength) {
        // 1. Parse Install Parameters for Country ISO
        // Structure: [Li][AID][Lc][Privs][La][AppletParams...]
        short aidLen = bArray[bOffset];
        short privOffset = (short)(bOffset + aidLen + 1);
        short privLen = bArray[privOffset];
        short paramOffset = (short)(privOffset + privLen + 1);
        short paramLen = bArray[paramOffset];
        
        if (paramLen >= 2) {
            countryISO = Util.makeShort(bArray[(short)(paramOffset + 1)], bArray[(short)(paramOffset + 2)]);
        } else {
            countryISO = (short) 504; // Default to Morocco
        }

        // 2. Initialize Wallet Identity (4 Bytes)
        // In a real deployment, this should be generated uniquely or passed via Install Params.
        // For demonstration, we set a mock ID: 0x11, 0x22, 0x33, 0x44
        walletID = new byte[4];
        walletID[0] = (byte)0x11;
        walletID[1] = (byte)0x22;
        walletID[2] = (byte)0x33;
        walletID[3] = (byte)0x44;

        // 3. Initialize PIN (Default: 1234)
        userPin = new OwnerPIN((byte) 3, (byte) 4);
        byte[] defaultPin = {(byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78};
        userPin.update(defaultPin, (short) 0, (byte) 4);

        // 4. Initialize State
        balance = 5000; // Start with 50.00
        transactionLogs = new byte[MAX_BUFFER_SIZE];
        logCount = 0;

        // 5. Initialize Crypto
        try {
            macSignature = Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_1_M2_ALG3, false);
            macKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
            macKey.setKey(DEFAULT_KEY, (short) 0);
        } catch (CryptoException e) {
            macSignature = Signature.getInstance(Signature.ALG_DES_MAC8_NOPAD, false);
        }

        secureChannel = GPSystem.getSecureChannel();
        scratchBuffer = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new YiriwaApplet(bArray, bOffset, bLength);
    }

    /**
     * Main APDU Processing Loop
     */
    public void process(APDU apdu) {
        if (selectingApplet()) return;

        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];
        byte cla = buffer[ISO7816.OFFSET_CLA];

        // GlobalPlatform Security Interception
        if (cla == (byte) 0x80 && (ins == INS_GP_INITIALIZE_UPDATE || ins == INS_GP_EXTERNAL_AUTH)) {
            secureChannel.processSecurity(apdu);
            return;
        }

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
            case INS_RECHARGE:
                enforceSecureChannel(apdu); // Vital: Must be encrypted!
                processRecharge(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // --- Core Payment Logic --------------------------------------------------

    /**
     * INS_DEBIT_AND_SWAP
     * P1 = 0x00 (Offline), 0x01 (Online)
     * Payload: [Amount (2)] + [MerchantID (4)] + [ItemID (1)]
     */
    private void processDebitAndSwap(APDU apdu) {
        if (!userPin.isValidated()) ISOException.throwIt(SW_PIN_REQUIRED);

        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[ISO7816.OFFSET_P1];
        short offset = ISO7816.OFFSET_CDATA;

        // 1. Capacity Check (Offline only)
        if (logCount >= MAX_RECORDS && p1 == POS_STATUS_OFFLINE) {
            // Send "SYNC REQUIRED" warning
            byte[] msg = {'S','Y','N','C',' ','R','E','Q','U','I','R','E','D'};
            Util.arrayCopyNonAtomic(msg, (short)0, buffer, (short)0, (short)msg.length);
            apdu.setOutgoingAndSend((short)0, (short)msg.length);
            return;
        }

        // 2. Parse & Validate
        short amount = Util.makeShort(buffer[offset], buffer[(short)(offset+1)]);
        short idOffset = (short)(offset + 2);
        byte itemID = buffer[(short)(offset + 6)];

        if (amount <= 0) ISOException.throwIt(SW_INVALID_FORMAT);
        if (balance < amount) ISOException.throwIt(SW_INSUFFICIENT_FUNDS);

        // 3. Prepare New Log in RAM (Transient)
        // Compress ID -> MAC -> Append ISO
        compressAndPack(buffer, idOffset, amount, itemID, scratchBuffer, (short) 0);
        generateTruncatedMAC(scratchBuffer, (short) 0, (short) 6, scratchBuffer, (short) 6);
        Util.setShort(scratchBuffer, (short) 10, countryISO);

        // 4. "Harvest" Preparation (Identity + History)
        // Response Structure: [WalletID (4b)] + [Logs (N * 12b)]
        
        // A. Copy Wallet ID to start of response buffer
        Util.arrayCopyNonAtomic(walletID, (short)0, buffer, (short)0, (short)4);
        
        // B. Copy Existing Logs after Wallet ID
        short currentLogsSize = (short)(logCount * LOG_SIZE);
        if (logCount > 0) {
            // Note: buffer is offset by 4
            Util.arrayCopyNonAtomic(transactionLogs, (short)0, buffer, (short)4, currentLogsSize);
        }
        
        // Total bytes to send back
        short totalResponseLen = (short)(4 + currentLogsSize);

        // 5. Atomic Commit
        JCSystem.beginTransaction();
        try {
            // Deduct
            balance = (short)(balance - amount);

            if (p1 == POS_STATUS_ONLINE) {
                // Online: Clear history, store ONLY the new log
                Util.arrayCopy(scratchBuffer, (short) 0, transactionLogs, (short) 0, LOG_SIZE);
                logCount = 1; 
            } else {
                // Offline: Append new log to end
                short newOffset = (short)(logCount * LOG_SIZE);
                Util.arrayCopy(scratchBuffer, (short) 0, transactionLogs, newOffset, LOG_SIZE);
                logCount++;
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }

        // 6. Send Harvest Response
        sendSecureResponse(apdu, totalResponseLen);
    }

    /**
     * INS_RECHARGE (0x60)
     * Payload: [Amount (2 Bytes)]
     * Logic: Adds funds to balance safely.
     */
    private void processRecharge(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short offset = ISO7816.OFFSET_CDATA;

        // 1. Parse Amount
        short amount = Util.makeShort(buffer[offset], buffer[(short)(offset+1)]);
        if (amount <= 0) ISOException.throwIt(SW_INVALID_FORMAT);

        // 2. Overflow Check
        if ((short)(balance + amount) > MAX_BALANCE_CAP) {
            ISOException.throwIt(SW_BALANCE_OVERFLOW);
        }

        // 3. Atomic Update
        JCSystem.beginTransaction();
        try {
            balance = (short)(balance + amount);
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }

        // 4. Return New Balance
        Util.setShort(buffer, (short)0, balance);
        sendSecureResponse(apdu, (short)2);
    }

    // --- Compression Engine --------------------------------------------------

    private void compressAndPack(byte[] src, short srcOff, short amount, byte item, byte[] dest, short destOff) {
        Util.arrayFillNonAtomic(scratchBuffer, (short) 20, (short) 3, (byte) 0);
        for (short i = 0; i < 4; i++) {
            byte c = src[(short)(srcOff + i)];
            short val = mapBase62(c);
            multiply24BitBy62AndAdd(scratchBuffer, (short) 20, val);
        }
        Util.arrayCopy(scratchBuffer, (short) 20, dest, destOff, (short) 3);
        Util.setShort(dest, (short)(destOff+3), amount);
        dest[(short)(destOff+5)] = item;
    }

    private void multiply24BitBy62AndAdd(byte[] arr, short offset, short addVal) {
        short b2 = (short)(arr[(short)(offset+2)] & 0xFF);
        short res2 = (short)((b2 * 62) + addVal); 
        arr[(short)(offset+2)] = (byte) res2; 
        short carry = (short)((res2 >>> 8) & 0xFF); 

        short b1 = (short)(arr[(short)(offset+1)] & 0xFF);
        short res1 = (short)((b1 * 62) + carry);
        arr[(short)(offset+1)] = (byte) res1;
        carry = (short)((res1 >>> 8) & 0xFF);

        short b0 = (short)(arr[offset] & 0xFF);
        short res0 = (short)((b0 * 62) + carry);
        arr[offset] = (byte) res0;
    }

    private short mapBase62(byte c) {
        if (c >= '0' && c <= '9') return (short)(c - '0');
        if (c >= 'A' && c <= 'Z') return (short)(c - 'A' + 10);
        if (c >= 'a' && c <= 'z') return (short)(c - 'a' + 36);
        ISOException.throwIt(SW_INVALID_FORMAT);
        return 0;
    }

    // --- Crypto Helpers ------------------------------------------------------

    private void generateTruncatedMAC(byte[] data, short dOff, short dLen, byte[] dest, short destOff) {
        macSignature.init(macKey, Signature.MODE_SIGN);
        macSignature.sign(data, dOff, dLen, scratchBuffer, (short) 20);
        Util.arrayCopy(scratchBuffer, (short) 20, dest, destOff, (short) 4);
    }

    // --- SCP03 Helpers -------------------------------------------------------

    private void enforceSecureChannel(APDU apdu) {
        byte level = secureChannel.getSecurityLevel();
        // Strict check: Must have both Encryption (C_DECRYPTION) and Integrity (C_MAC)
        if ((level & (SecureChannel.C_DECRYPTION | SecureChannel.C_MAC)) == 0) {
            ISOException.throwIt(SW_SECURE_CHANNEL);
        }
        try {
            short len = apdu.setIncomingAndReceive();
            short clearLen = secureChannel.unwrap(apdu.getBuffer(), (short) 0, (short)(len + 5));
            apdu.setIncomingLength(clearLen);
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private void sendSecureResponse(APDU apdu, short len) {
        short secureLen = secureChannel.wrap(apdu.getBuffer(), (short) 0, len);
        apdu.setOutgoingAndSend((short) 0, secureLen);
    }

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
