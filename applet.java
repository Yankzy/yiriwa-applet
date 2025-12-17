package com.yiriwa.wallet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
import org.globalplatform.*;

/**
 * =========================================================================================
 * Yiriwa Trusted Carrier Applet v4.0 (ZK-Carrier Protocol)
 * =========================================================================================
 *
 * OVERVIEW:
 * This Applet implements the "Trusted Applet-Driven Compression" mechanism.
 * Ideally suited for constrained storage environments, it shifts the compression
 * trust anchor from the Merchant to the Secure Element (SE).
 *
 * -----------------------------------------------------------------------------------------
 * CORE INNOVATION: ATOMIC COMPRESSION & SIGNING
 * Instead of storing full JSON logs, the Applet:
 * 1. Accepts raw transaction data (Amount, MerchantID, Item).
 * 2. Compresses it using internal logic (Base62 decoding + Bit-packing).
 * 3. Signs the compressed blob with the Card's Private Key.
 * 4. Stores the blob atomically with the balance decrement.
 *
 * [Storage Format - 6 Bytes]
 * Byte 0-2: Merchant ID (Compressed from 4 Base62 chars)
 * Byte 3-4: Amount (Unsigned Short)
 * Byte 5:   Item Category ID
 *
 * -----------------------------------------------------------------------------------------
 * APDU INTERFACE:
 * CLA: 0x80 (0x84 for SCP03 Wrapped)
 *
 * [INS_GET_LAST_LOG - 0x50]
 * - Returns: [Compressed_Blob (6B)] [Signature_Len (2B)] [Signature (Var)]
 *
 * [INS_DEBIT - 0x40]
 * - Input: [Amount (2B)] [MID_String (4B)] [Item_ID (1B)]
 * - Logic: Decrements balance AND overwrites the Last Log in one atomic commit.
 * -----------------------------------------------------------------------------------------
 */
public class YiriwaApplet extends Applet {

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------
    private static final byte CLA_YIRIWA          = (byte) 0x80;
    
    private static final byte INS_VERIFY_PIN      = (byte) 0x20;
    private static final byte INS_GET_BALANCE     = (byte) 0x30;
    private static final byte INS_DEBIT           = (byte) 0x40; // Overwrite old log
    private static final byte INS_GET_LAST_LOG    = (byte) 0x50; // Harvest old log

    // GlobalPlatform
    private static final byte INS_GP_INITIALIZE_UPDATE = (byte) 0x50;
    private static final byte INS_GP_EXTERNAL_AUTH     = (byte) 0x82;
    
    // Status Words
    private static final short SW_PIN_REQUIRED     = (short) 0x6301;
    private static final short SW_INSUFFICIENT_FUNDS = (short) 0x6910;
    private static final short SW_INVALID_FORMAT     = (short) 0x6911;
    private static final short SW_SECURE_CHANNEL     = (short) 0x6982;

    // -------------------------------------------------------------------------
    // State (EEPROM)
    // -------------------------------------------------------------------------
    private OwnerPIN userPin;
    private short balance; // Simplified to short for demo (0-32767)
    
    // THE CARRIER PAYLOAD (Storage Optimized)
    private byte[] lastLogData;      // Fixed 6 bytes
    private byte[] lastLogSignature; // Max ~72 bytes for ECDSA
    private short  lastLogSigLen;    // Actual length of current sig

    // -------------------------------------------------------------------------
    // Crypto (RAM)
    // -------------------------------------------------------------------------
    private KeyPair keyPair;
    private Signature ecdsaSignature;
    private SecureChannel secureChannel;
    private byte[] scratchBuffer;

    /**
     * Constructor
     */
    private YiriwaApplet(byte[] bArray, short bOffset, byte bLength) {
        // 1. PIN Init
        userPin = new OwnerPIN((byte) 3, (byte) 8);
        byte[] defaultPin = {(byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34};
        userPin.update(defaultPin, (short) 0, (byte) defaultPin.length);

        // 2. State Init
        balance = 10000; 
        
        // Alloc storage for the Compressed Blob
        lastLogData = new byte[6]; 
        lastLogSignature = new byte[80]; // Buffer for sig
        lastLogSigLen = 0;

        // 3. Crypto Init
        try {
            keyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
            keyPair.genKeyPair();
            ecdsaSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        secureChannel = GPSystem.getSecureChannel();
        scratchBuffer = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_DESELECT);

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new YiriwaApplet(bArray, bOffset, bLength);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;

        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];
        byte cla = buffer[ISO7816.OFFSET_CLA];

        // GP Secure Channel Passthrough
        if (cla == (byte) 0x80 && (ins == INS_GP_INITIALIZE_UPDATE || ins == INS_GP_EXTERNAL_AUTH)) {
            secureChannel.processSecurity(apdu);
            return;
        }

        // Applet Commands
        if ((cla & (byte) 0xFC) != CLA_YIRIWA) ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        switch (ins) {
            case INS_VERIFY_PIN:
                enforceSecureChannel(apdu);
                verifyPin(apdu);
                break;
            case INS_GET_BALANCE:
                enforceSecureChannel(apdu);
                getBalance(apdu);
                break;
            case INS_GET_LAST_LOG:
                // Allows Merchant B to "Harvest" the previous state
                // No PIN required for harvesting (public audit), but usually Auth required
                returnLastLog(apdu);
                break;
            case INS_DEBIT:
                enforceSecureChannel(apdu);
                processAtomicDebitAndLog(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // --- Core Logic ----------------------------------------------------------

    /**
     * INS_DEBIT: Atomic Debit + Compression + Signing
     * Input: [Amount(2)] [MID_String(4)] [Item_ID(1)] = 7 Bytes
     */
    private void processAtomicDebitAndLog(APDU apdu) {
        if (!userPin.isValidated()) ISOException.throwIt(SW_PIN_REQUIRED);

        byte[] buffer = apdu.getBuffer();
        short offset = ISO7816.OFFSET_CDATA;

        // 1. Parse Inputs
        // Amount (2 bytes)
        short amount = Util.makeShort(buffer[offset], buffer[(short)(offset+1)]);
        
        // Merchant ID (4 bytes ASCII, e.g., "0uAi")
        short midOffset = (short)(offset + 2);
        
        // Item ID (1 byte)
        byte itemID = buffer[(short)(offset + 6)];

        // 2. Financial Validation
        if (amount <= 0) ISOException.throwIt(SW_INVALID_FORMAT);
        if (balance < amount) ISOException.throwIt(SW_INSUFFICIENT_FUNDS);

        // 3. Compress Data (The Innovation)
        // We do this BEFORE opening the transaction to fail fast if inputs are bad
        // Output goes to scratchBuffer[0..5]
        compressAndPack(buffer, midOffset, amount, itemID, scratchBuffer, (short) 0);

        // 4. Sign the Compressed Blob
        ecdsaSignature.init(keyPair.getPrivate(), Signature.MODE_SIGN);
        // Sign the 6 bytes in scratchBuffer
        short sigLen = ecdsaSignature.sign(scratchBuffer, (short) 0, (short) 6, scratchBuffer, (short) 10);
        // Signature is now at scratchBuffer[10...10+sigLen]

        // 5. ATOMIC COMMIT (Debit + Log Overwrite)
        JCSystem.beginTransaction();
        try {
            // A. Debit
            balance = (short)(balance - amount);

            // B. Store Log Data (6 Bytes)
            Util.arrayCopy(scratchBuffer, (short) 0, lastLogData, (short) 0, (short) 6);

            // C. Store Signature
            lastLogSigLen = sigLen;
            Util.arrayCopy(scratchBuffer, (short) 10, lastLogSignature, (short) 0, sigLen);

            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }

        // 6. Response (Success)
        sendSecureResponse(apdu, (short) 0);
    }

    /**
     * INS_GET_LAST_LOG
     * Response: [Blob(6)] [SigLen(2)] [Sig(Var)]
     */
    private void returnLastLog(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        
        // 1. Copy Blob
        Util.arrayCopy(lastLogData, (short) 0, buffer, (short) 0, (short) 6);
        
        // 2. Copy Sig Len
        Util.setShort(buffer, (short) 6, lastLogSigLen);
        
        // 3. Copy Signature
        Util.arrayCopy(lastLogSignature, (short) 0, buffer, (short) 8, lastLogSigLen);
        
        apdu.setOutgoingAndSend((short) 0, (short)(8 + lastLogSigLen));
    }

    // --- Helper: Compression Engine ------------------------------------------

    /**
     * Compresses the transaction into 6 bytes.
     * Logic:
     * - Convert 4-char Base62 MID -> 3-byte Integer (24 bits)
     * - Pack Amount (16 bits)
     * - Pack Item (8 bits)
     * Total: 48 bits = 6 bytes.
     */
    private void compressAndPack(byte[] src, short midOff, short amount, byte item, byte[] dest, short destOff) {
        // A. Base62 Compression (4 bytes -> 3 bytes)
        // val = c0*62^3 + c1*62^2 + c2*62^1 + c3
        // We use 'int' (32-bit) accumulator. 
        // Note: 62^3 = 238,328. 4 chars fits in signed int (max 2B).
        
        int acc = 0;
        int power = 238328; // 62^3
        
        for (short i = 0; i < 4; i++) {
            byte charByte = src[(short)(midOff + i)];
            short val = mapBase62(charByte);
            acc += (val * power);
            power /= 62;
        }

        // Write 3 bytes of MID (from 32-bit int)
        // We skip the highest byte (which should be 0)
        dest[destOff]     = (byte) (acc >> 16);
        dest[(short)(destOff+1)] = (byte) (acc >> 8);
        dest[(short)(destOff+2)] = (byte) (acc);

        // B. Write Amount (2 bytes)
        Util.setShort(dest, (short)(destOff+3), amount);

        // C. Write Item (1 byte)
        dest[(short)(destOff+5)] = item;
    }

    /**
     * Maps ASCII [0-9, A-Z, a-z] to 0-61.
     */
    private short mapBase62(byte c) {
        if (c >= '0' && c <= '9') return (short)(c - '0');       // 0-9
        if (c >= 'A' && c <= 'Z') return (short)(c - 'A' + 10);  // 10-35
        if (c >= 'a' && c <= 'z') return (short)(c - 'a' + 36);  // 36-61
        ISOException.throwIt(SW_INVALID_FORMAT);
        return 0;
    }

    // --- Boilerplate Helpers -------------------------------------------------

    private void enforceSecureChannel(APDU apdu) {
        byte level = secureChannel.getSecurityLevel();
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
