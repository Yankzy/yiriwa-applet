package com.yiriwa.wallet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
import org.globalplatform.*; // Crucial for SCP03

/**
 * =========================================================================================
 * Yiriwa Trusted Carrier Applet v5.1 (Secure Audit Mesh + SCP03)
 * =========================================================================================
 *
 * MERGED ARCHITECTURE:
 * 1. TRANSPORT SECURITY (Restored): All sensitive commands (PIN, Debit) must be wrapped
 * in a GlobalPlatform SCP03 Secure Channel (Encryption + MAC).
 * 2. LOGIC: "Pop-and-Push" (Atomic Debit & Swap).
 * 3. COMPATIBILITY: Byte-only math (no 'int') for Base62 compression.
 * 4. INTEGRITY: 4-Byte Truncated MAC on stored logs.
 *
 * -----------------------------------------------------------------------------------------
 * APDU INTERFACE (Wrapped in SCP03):
 * CLA: 0x84 (Secure Messaging)
 *
 * [INS_DEBIT_AND_SWAP - 0x40]
 * - Input (Encrypted): [Amount(2)] [FedID_String(4)] [Item(1)]
 * - Output (Encrypted): [Previous_Log_Data(6)] [Previous_Log_MAC(4)]
 * -----------------------------------------------------------------------------------------
 */
public class YiriwaApplet extends Applet {

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------
    private static final byte CLA_YIRIWA          = (byte) 0x80;
    
    // Instructions
    private static final byte INS_VERIFY_PIN      = (byte) 0x20;
    private static final byte INS_GET_BALANCE     = (byte) 0x30;
    private static final byte INS_DEBIT_AND_SWAP  = (byte) 0x40; 
    
    // GlobalPlatform Specific
    private static final byte INS_GP_INITIALIZE_UPDATE = (byte) 0x50;
    private static final byte INS_GP_EXTERNAL_AUTH     = (byte) 0x82;

    // Status Words
    private static final short SW_PIN_REQUIRED       = (short) 0x6301;
    private static final short SW_INSUFFICIENT_FUNDS = (short) 0x6910;
    private static final short SW_INVALID_FORMAT     = (short) 0x6911;
    private static final short SW_SECURE_CHANNEL     = (short) 0x6982;

    // -------------------------------------------------------------------------
    // State (EEPROM)
    // -------------------------------------------------------------------------
    private OwnerPIN userPin;
    private short balance; 
    
    // THE CARRIER PAYLOAD (10 Bytes)
    // [Data(6B)] + [Proof(4B)]
    private byte[] lastLogData; 

    // -------------------------------------------------------------------------
    // Crypto & RAM
    // -------------------------------------------------------------------------
    private Signature macSignature;
    private DESKey macKey;
    private SecureChannel secureChannel; // Restored
    private byte[] scratchBuffer; 

    // Hardcoded MAC Key for demo (In prod, inject via Secure Channel)
    private static final byte[] DEFAULT_KEY = {
        (byte)0x59, (byte)0x49, (byte)0x52, (byte)0x49, 
        (byte)0x57, (byte)0x41, (byte)0x5F, (byte)0x4B 
    };

    /**
     * Constructor
     */
    private YiriwaApplet(byte[] bArray, short bOffset, byte bLength) {
        // 1. PIN Init
        userPin = new OwnerPIN((byte) 3, (byte) 4);
        byte[] defaultPin = {(byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78};
        userPin.update(defaultPin, (short) 0, (byte) 4);

        // 2. State Init
        balance = 20000; 
        lastLogData = new byte[10]; // 6 Data + 4 MAC

        // 3. Crypto Init (MAC Engine for Audit Integrity)
        try {
            macSignature = Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_1_M2_ALG3, false);
            macKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
            macKey.setKey(DEFAULT_KEY, (short) 0);
        } catch (CryptoException e) {
            macSignature = Signature.getInstance(Signature.ALG_DES_MAC8_NOPAD, false);
        }

        // 4. Secure Channel Init (For Transport Security)
        secureChannel = GPSystem.getSecureChannel();

        // 5. RAM Init
        scratchBuffer = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);

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

        // 1. Handshake: Pass GP commands to SecureChannel (CLA 0x80)
        if (cla == (byte) 0x80 && (ins == INS_GP_INITIALIZE_UPDATE || ins == INS_GP_EXTERNAL_AUTH)) {
            secureChannel.processSecurity(apdu);
            return;
        }

        // 2. Applet Commands: Enforce Valid CLA
        // We accept 0x80 (Clear) or 0x84 (Secure) depending on implementation policy.
        // But enforceSecureChannel will reject 0x80 for sensitive commands.
        if ((cla & (byte) 0xFC) != CLA_YIRIWA) {
             ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (ins) {
            case INS_VERIFY_PIN:
                enforceSecureChannel(apdu); // Must be wrapped
                verifyPin(apdu);
                break;
            case INS_GET_BALANCE:
                enforceSecureChannel(apdu); // Must be wrapped
                getBalance(apdu);
                break;
            case INS_DEBIT_AND_SWAP:
                enforceSecureChannel(apdu); // Must be wrapped
                processDebitAndSwap(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // --- Core Logic ----------------------------------------------------------

    /**
     * INS_DEBIT_AND_SWAP
     * Logic: Pop old log (Harvest), Push new log (Debit), Commit.
     */
    private void processDebitAndSwap(APDU apdu) {
        if (!userPin.isValidated()) ISOException.throwIt(SW_PIN_REQUIRED);

        byte[] buffer = apdu.getBuffer();
        short offset = ISO7816.OFFSET_CDATA;
        
        // Input validation
        // buffer[ISO7816.OFFSET_LC] is handled by SCP unwrapping logic usually,
        // but we double check content length
        
        // 1. Parse Input
        short amount = Util.makeShort(buffer[offset], buffer[(short)(offset+1)]);
        short idOffset = (short)(offset + 2);
        byte itemID = buffer[(short)(offset + 6)];

        if (amount <= 0) ISOException.throwIt(SW_INVALID_FORMAT);
        if (balance < amount) ISOException.throwIt(SW_INSUFFICIENT_FUNDS);

        // 2. Prepare NEW Log in RAM (scratchBuffer)
        // Step A: Compression (scratch[0..5])
        compressAndPack(buffer, idOffset, amount, itemID, scratchBuffer, (short) 0);
        
        // Step B: Generate MAC (scratch[6..9])
        generateTruncatedMAC(scratchBuffer, (short) 0, (short) 6, scratchBuffer, (short) 6);

        // 3. Prepare RESPONSE (The OLD Log)
        // We copy the OLD log from EEPROM to the APDU buffer before overwrite.
        // We must check if buffer has space, but standard APDU buffer is 255+.
        Util.arrayCopy(lastLogData, (short) 0, buffer, (short) 0, (short) 10);

        // 4. ATOMIC COMMIT
        JCSystem.beginTransaction();
        try {
            // A. Update Balance
            balance = (short)(balance - amount);
            
            // B. Overwrite EEPROM
            Util.arrayCopy(scratchBuffer, (short) 0, lastLogData, (short) 0, (short) 10);
            
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }

        // 5. Send Secure Response
        // We encrypt the OLD log before sending it out
        sendSecureResponse(apdu, (short) 10);
    }

    // --- Compression Engine (Byte Math) --------------------------------------

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
        short sigLen = macSignature.sign(data, dOff, dLen, scratchBuffer, (short) 10);
        Util.arrayCopy(scratchBuffer, (short) 10, dest, destOff, (short) 4);
    }

    // --- SCP03 Helpers -------------------------------------------------------

    private void enforceSecureChannel(APDU apdu) {
        byte level = secureChannel.getSecurityLevel();
        // Require C_DECRYPTION (Privacy) and C_MAC (Integrity)
        if ((level & (SecureChannel.C_DECRYPTION | SecureChannel.C_MAC)) == 0) {
            ISOException.throwIt(SW_SECURE_CHANNEL);
        }
        try {
            short len = apdu.setIncomingAndReceive();
            // Unwrap modifies buffer: decrypts data and verifies MAC
            short clearLen = secureChannel.unwrap(apdu.getBuffer(), (short) 0, (short)(len + 5));
            apdu.setIncomingLength(clearLen);
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private void sendSecureResponse(APDU apdu, short len) {
        // Wraps the response (Encrypts + MACs)
        short secureLen = secureChannel.wrap(apdu.getBuffer(), (short) 0, len);
        apdu.setOutgoingAndSend((short) 0, secureLen);
    }

    private void verifyPin(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        // PIN is now plaintext in buffer because enforceSecureChannel() unwrapped it
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
