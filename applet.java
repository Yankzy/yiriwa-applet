package com.yiriwa.wallet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
import org.globalplatform.*; 

public class YiriwaApplet extends Applet {

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------
    private static final byte CLA_YIRIWA          = (byte) 0x80;
    private static final byte INS_VERIFY_PIN      = (byte) 0x20;
    private static final byte INS_GET_BALANCE     = (byte) 0x30;
    private static final byte INS_DEBIT_AND_SWAP  = (byte) 0x40; 
    
    // GP Constants
    private static final byte INS_GP_INITIALIZE_UPDATE = (byte) 0x50;
    private static final byte INS_GP_EXTERNAL_AUTH     = (byte) 0x82;

    // Errors
    private static final short SW_PIN_REQUIRED       = (short) 0x6301;
    private static final short SW_INSUFFICIENT_FUNDS = (short) 0x6910;
    private static final short SW_INVALID_FORMAT     = (short) 0x6911;
    private static final short SW_SECURE_CHANNEL     = (short) 0x6982;

    // Configuration
    // 6 Bytes Data + 4 Bytes MAC + 2 Bytes ISO Suffix = 12 Bytes
    private static final byte LOG_SIZE = (byte) 12; 

    // -------------------------------------------------------------------------
    // State (EEPROM)
    // -------------------------------------------------------------------------
    private OwnerPIN userPin;
    private short balance; 
    private byte[] lastLogData; 
    
    // Persistent Storage for Country ISO (e.g., 504 for Morocco)
    private short countryISO; 

    // -------------------------------------------------------------------------
    // Crypto & RAM
    // -------------------------------------------------------------------------
    private Signature macSignature;
    private DESKey macKey;
    private SecureChannel secureChannel;
    private byte[] scratchBuffer; 

    private static final byte[] DEFAULT_KEY = {
        (byte)0x59, (byte)0x49, (byte)0x52, (byte)0x49, 
        (byte)0x57, (byte)0x41, (byte)0x5F, (byte)0x4B 
    };

    /**
     * Constructor
     */
    private YiriwaApplet(byte[] bArray, short bOffset, byte bLength) {
        // 1. Parse Install Parameters to find Country ISO
        // Structure: [Li][InstanceAID][Lc][Privileges][La][AppletParams]
        
        // Skip Instance AID
        short aidLen = bArray[bOffset];
        short privOffset = (short)(bOffset + aidLen + 1);
        
        // Skip Privileges
        short privLen = bArray[privOffset];
        short paramOffset = (short)(privOffset + privLen + 1);
        
        // Read Applet Specific Parameters (Length is at paramOffset)
        short paramLen = bArray[paramOffset];
        
        // We expect at least 2 bytes for the Country ISO (short)
        if (paramLen >= 2) {
            // Read 2 bytes from paramOffset + 1
            countryISO = Util.makeShort(bArray[(short)(paramOffset + 1)], bArray[(short)(paramOffset + 2)]);
        } else {
            // Default to 0 if not supplied (or throw exception)
            countryISO = (short) 0; 
        }

        // 2. PIN Init
        userPin = new OwnerPIN((byte) 3, (byte) 4);
        byte[] defaultPin = {(byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78};
        userPin.update(defaultPin, (short) 0, (byte) 4);

        // 3. State Init
        balance = 20000; 
        lastLogData = new byte[LOG_SIZE]; // Now 12 Bytes

        // 4. Crypto Init
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

    public void process(APDU apdu) {
        if (selectingApplet()) return;

        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];
        byte cla = buffer[ISO7816.OFFSET_CLA];

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
        
        // 1. Parse Input
        short amount = Util.makeShort(buffer[offset], buffer[(short)(offset+1)]);
        short idOffset = (short)(offset + 2);
        byte itemID = buffer[(short)(offset + 6)];

        if (amount <= 0) ISOException.throwIt(SW_INVALID_FORMAT);
        if (balance < amount) ISOException.throwIt(SW_INSUFFICIENT_FUNDS);

        // 2. Prepare NEW Log in RAM (scratchBuffer)
        // Step A: Compression (Bytes 0-5)
        compressAndPack(buffer, idOffset, amount, itemID, scratchBuffer, (short) 0);
        
        // Step B: Generate MAC (Bytes 6-9)
        generateTruncatedMAC(scratchBuffer, (short) 0, (short) 6, scratchBuffer, (short) 6);
        
        // NEW Step C: Append Country ISO Suffix (Bytes 10-11)
        Util.setShort(scratchBuffer, (short) 10, countryISO);

        // 3. Prepare RESPONSE (The OLD Log)
        // Copy the old 12-byte log from EEPROM to APDU buffer
        Util.arrayCopy(lastLogData, (short) 0, buffer, (short) 0, LOG_SIZE);

        // 4. ATOMIC COMMIT
        JCSystem.beginTransaction();
        try {
            balance = (short)(balance - amount);
            // Overwrite EEPROM with new 12-byte log
            Util.arrayCopy(scratchBuffer, (short) 0, lastLogData, (short) 0, LOG_SIZE);
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }

        // 5. Send Secure Response (12 Bytes)
        sendSecureResponse(apdu, LOG_SIZE);
    }

    // --- Compression Engine (No changes needed here) ---

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

    // --- Crypto Helpers ---

    private void generateTruncatedMAC(byte[] data, short dOff, short dLen, byte[] dest, short destOff) {
        macSignature.init(macKey, Signature.MODE_SIGN);
        short sigLen = macSignature.sign(data, dOff, dLen, scratchBuffer, (short) 20);
        // Copy only first 4 bytes
        Util.arrayCopy(scratchBuffer, (short) 20, dest, destOff, (short) 4);
    }

    // --- SCP03 Helpers ---

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
