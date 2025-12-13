package com.yiriwa.wallet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/**
 * Yiriwa Offline Protocol (YOP) v2.0 Applet
 * Implements Secure Offline Value Transfer with PIN Authentication.
 * Target: JCOP 3.0.4+ / Java Card 3.0.5
 */
public class YiriwaApplet extends Applet {

    // -------------------------------------------------------------------------
    // Constants (Instructions & Status Words)
    // -------------------------------------------------------------------------
    private static final byte CLA_YIRIWA            = (byte) 0x80;
    
    // Instruction Codes
    private static final byte INS_VERIFY_PIN        = (byte) 0x20;
    private static final byte INS_GET_BALANCE       = (byte) 0x30;
    private static final byte INS_DEBIT             = (byte) 0x40;
    
    // Yiriwa Specific Status Words
    private static final short SW_PIN_VERIFICATION_REQUIRED = (short) 0x6301;
    private static final short SW_NEGATIVE_BALANCE          = (short) 0x6910;
    private static final short SW_INVALID_AMOUNT            = (short) 0x6911;

    // Configuration
    private static final byte PIN_TRY_LIMIT         = (byte) 3;
    private static final byte PIN_MAX_SIZE          = (byte) 8;
    private static final short INITIAL_BALANCE      = (short) 10000; // Demo Balance
    
    // -------------------------------------------------------------------------
    // Instance Variables (Persistent State in EEPROM)
    // -------------------------------------------------------------------------
    private OwnerPIN userPin;
    private long shadowBalance; // Stored as 8 bytes, simplified here as long logic
    private int nonce;          // 4 bytes counter
    
    // Crypto Objects
    private KeyPair keyPair;
    private Signature ecdsaSignature;
    private byte[] scratchBuffer; // RAM buffer for temporary data

    /**
     * Constructor: Initialize memory and keys
     */
    private YiriwaApplet(byte[] bArray, short bOffset, byte bLength) {
        // 1. Initialize PIN
        userPin = new OwnerPIN(PIN_TRY_LIMIT, PIN_MAX_SIZE);
        // Hardcoded Default PIN: "1234" (For development only)
        byte[] defaultPin = {(byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34};
        userPin.update(defaultPin, (short) 0, (byte) defaultPin.length);

        // 2. Initialize State
        shadowBalance = INITIAL_BALANCE; // In minimal units (e.g. Dalasi cents)
        nonce = 1;

        // 3. Generate Keys (Secp256r1)
        // Note: On real cards, keys are often injected, not generated in constructor to save time
        try {
            keyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
            keyPair.genKeyPair();
            ecdsaSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        } catch (Exception e) {
            // Fallback for older cards or simulation issues
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        // 4. Allocate RAM buffer (avoid EEPROM wear for temp data)
        scratchBuffer = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);

        register();
    }

    /**
     * Installs the applet on the card.
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new YiriwaApplet(bArray, bOffset, bLength);
    }

    /**
     * Main Process Loop
     */
    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        
        // Check CLA (Class Byte)
        if (buffer[ISO7816.OFFSET_CLA] != CLA_YIRIWA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_VERIFY_PIN:
                verifyPin(apdu);
                break;
            case INS_GET_BALANCE:
                getBalance(apdu);
                break;
            case INS_DEBIT:
                processDebit(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * Step 3: Cardholder Verification Method (CVM)
     * Checks the PIN sent by the terminal.
     */
    private void verifyPin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte byteRead = (byte) apdu.setIncomingAndReceive();

        // Verify PIN against stored hash
        if (userPin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        
        // If successful, returns 9000 by default
    }

    /**
     * Returns the current Shadow Balance (for UI display).
     * Security: Requires PIN validation first.
     */
    private void getBalance(APDU apdu) {
        if (!userPin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buffer = apdu.getBuffer();
        
        // Serialize long balance to 8 bytes
        // Note: Java Card doesn't support 'long' natively on all chips, 
        // usually we use byte arrays. This is a logic abstraction.
        Util.setShort(buffer, (short) 0, (short) 0); // High bytes padding
        Util.setShort(buffer, (short) 2, (short) 0);
        Util.setShort(buffer, (short) 4, (short) (shadowBalance >> 16));
        Util.setShort(buffer, (short) 6, (short) shadowBalance);

        apdu.setOutgoingAndSend((short) 0, (short) 8);
    }

    /**
     * Step 3.5: On-Card Processing (The Atomic Swap)
     * 1. Check PIN
     * 2. Check Funds
     * 3. Atomic Decrement
     * 4. Sign Proof
     */
    private void processDebit(APDU apdu) {
        // 1. Security Check
        if (!userPin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();
        
        // Expected Payload: Amount (4) || MerchantID (8) || TerminalNonce (4) = 16 bytes
        if (bytesRead < 16) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Parse Amount (Assuming 4 bytes int for this implementation)
        // In production, we parse a proper 64-bit BigInt
        int amount = Util.makeShort(buffer[ISO7816.OFFSET_CDATA], buffer[(short)(ISO7816.OFFSET_CDATA+1)]) << 16 |
                     (Util.makeShort(buffer[(short)(ISO7816.OFFSET_CDATA+2)], buffer[(short)(ISO7816.OFFSET_CDATA+3)]) & 0xFFFF);

        if (amount <= 0) {
            ISOException.throwIt(SW_INVALID_AMOUNT);
        }

        // 2. Balance Check
        if (shadowBalance < amount) {
            ISOException.throwIt(SW_NEGATIVE_BALANCE);
        }

        // 3. ATOMIC STATE UPDATE
        // This ensures protection against tearing (power loss mid-write)
        JCSystem.beginTransaction();
        try {
            shadowBalance = shadowBalance - amount;
            nonce++;
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }

        // 4. GENERATE PROOF (Signature)
        // Data to Sign: Amount (4) + Nonce (4) + MerchantID (8)
        // Copy data to scratch buffer to arrange for signing
        short offset = 0;
        
        // A. Copy Amount (from APDU)
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, scratchBuffer, offset, (short) 4);
        offset += 4;
        
        // B. Copy Current Nonce (Internal State)
        Util.setShort(scratchBuffer, offset, (short) (nonce >> 16));
        Util.setShort(scratchBuffer, (short)(offset+2), (short) nonce);
        offset += 4;
        
        // C. Copy Merchant ID (from APDU)
        Util.arrayCopy(buffer, (short)(ISO7816.OFFSET_CDATA+4), scratchBuffer, offset, (short) 8);
        offset += 8;

        // Sign the data (16 bytes total)
        ecdsaSignature.init(keyPair.getPrivate(), Signature.MODE_SIGN);
        short sigLen = ecdsaSignature.sign(scratchBuffer, (short) 0, offset, buffer, (short) 0);
        
        // Append New Nonce to response (after signature)
        Util.setShort(buffer, sigLen, (short) (nonce >> 16));
        Util.setShort(buffer, (short)(sigLen+2), (short) nonce);
        
        // Send: Signature + NewNonce
        apdu.setOutgoingAndSend((short) 0, (short) (sigLen + 4));
    }
}
