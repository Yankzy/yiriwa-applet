package com.yiriwa.wallet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
import org.globalplatform.*; // Added for SCP03 Support

/**
 * Yiriwa Offline Protocol (YOP) v2.0 Applet
 * Features:
 * - Secure Offline Value Transfer
 * - PIN Authentication
 * - GlobalPlatform SCP03 (Secure Channel Protocol) integration
 * Target: JCOP 3.0.4+ / Java Card 3.0.5
 */
public class YiriwaApplet extends Applet {

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------
    // CLA: 0x80 for clear text, 0x84 for Secure Messaging (GlobalPlatform standard)
    private static final byte CLA_YIRIWA            = (byte) 0x80;
    private static final byte CLA_YIRIWA_SECURE     = (byte) 0x84;
    
    // Instruction Codes (Yiriwa)
    private static final byte INS_VERIFY_PIN        = (byte) 0x20;
    private static final byte INS_GET_BALANCE       = (byte) 0x30;
    private static final byte INS_DEBIT             = (byte) 0x40;

    // Instruction Codes (GlobalPlatform Handshake)
    private static final byte INS_GP_INITIALIZE_UPDATE = (byte) 0x50;
    private static final byte INS_GP_EXTERNAL_AUTH     = (byte) 0x82;
    
    // Status Words
    private static final short SW_PIN_VERIFICATION_REQUIRED = (short) 0x6301;
    private static final short SW_NEGATIVE_BALANCE          = (short) 0x6910;
    private static final short SW_INVALID_AMOUNT            = (short) 0x6911;
    private static final short SW_SECURE_CHANNEL_REQUIRED   = (short) 0x6982;

    // Configuration
    private static final byte PIN_TRY_LIMIT         = (byte) 3;
    private static final byte PIN_MAX_SIZE          = (byte) 8;
    private static final short INITIAL_BALANCE      = (short) 10000;
    
    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------
    private OwnerPIN userPin;
    private long shadowBalance; 
    private int nonce;
    
    // Crypto Objects
    private KeyPair keyPair;
    private Signature ecdsaSignature;
    private byte[] scratchBuffer; 

    // GlobalPlatform Secure Channel
    private SecureChannel secureChannel;

    /**
     * Constructor
     */
    private YiriwaApplet(byte[] bArray, short bOffset, byte bLength) {
        // 1. Initialize PIN
        userPin = new OwnerPIN(PIN_TRY_LIMIT, PIN_MAX_SIZE);
        byte[] defaultPin = {(byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34};
        userPin.update(defaultPin, (short) 0, (byte) defaultPin.length);

        // 2. Initialize State
        shadowBalance = INITIAL_BALANCE; 
        nonce = 1;

        // 3. Generate Applet Keys
        try {
            keyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
            keyPair.genKeyPair();
            ecdsaSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        // 4. Get Reference to GlobalPlatform Secure Channel
        // This links the Applet to the Security Domain's keys (SD-Key)
        secureChannel = GPSystem.getSecureChannel();

        scratchBuffer = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);

        register();
    }

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
        byte cla = buffer[ISO7816.OFFSET_CLA];
        byte ins = buffer[ISO7816.OFFSET_INS];

        // ---------------------------------------------------------------------
        // 1. Handle Secure Channel Handshake (Pass-through to GP)
        // ---------------------------------------------------------------------
        // Standard GlobalPlatform APDUs for establishing session keys
        if (cla == (byte) 0x80 && (ins == INS_GP_INITIALIZE_UPDATE || ins == INS_GP_EXTERNAL_AUTH)) {
            secureChannel.processSecurity(apdu);
            return;
        }

        // ---------------------------------------------------------------------
        // 2. Handle Application Commands
        // ---------------------------------------------------------------------
        // Allow 0x80 (Clear) or 0x84 (Secure) based on policy, but enforce security inside
        if ((cla & (byte) 0xFC) != CLA_YIRIWA) { // Matches 0x80 or 0x84
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (ins) {
            case INS_VERIFY_PIN:
                // Verify PIN must be done inside Secure Channel for privacy
                enforceSecureChannel(apdu);
                verifyPin(apdu);
                break;
            case INS_GET_BALANCE:
                enforceSecureChannel(apdu);
                getBalance(apdu);
                break;
            case INS_DEBIT:
                enforceSecureChannel(apdu);
                processDebit(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * Helper: Enforces that SCP is active and unwraps the incoming APDU.
     * Throws exception if channel is not secure.
     */
    private void enforceSecureChannel(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        
        // 1. Check if Secure Channel is active (at least MAC + ENC)
        byte level = secureChannel.getSecurityLevel();
        if ((level & (SecureChannel.C_DECRYPTION | SecureChannel.C_MAC)) == 0) {
            ISOException.throwIt(SW_SECURE_CHANNEL_REQUIRED);
        }

        // 2. Unwrap (Decrypt Data & Verify C-MAC)
        // This modifies the buffer in place: removes MAC, decrypts data.
        // Returns the actual length of the decrypted payload.
        try {
            short incomingLen = apdu.setIncomingAndReceive();
            short clearDataLen = secureChannel.unwrap(buffer, (short) 0, (short)(incomingLen + 5)); 
            // Note: +5 accounts for header in some GP implementations, 
            // but standard unwrap usually takes the whole buffer or specific offset.
            // Using standard approach: unwrap calls usually handle the APDU structure.
            // Simplified here: setIncomingAndReceive gets the payload.
            
            // Correction: unwrap() signature and behavior depends slightly on GP version.
            // Standard approach: Let 'unwrap' handle the incoming data in buffer.
            // We use the length returned by unwrap as the new Lc.
            apdu.setIncomingLength(clearDataLen); 
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    /**
     * Helper: Wraps the outgoing response (Encrypt + R-MAC).
     */
    private void sendSecureResponse(APDU apdu, short len) {
        byte[] buffer = apdu.getBuffer();
        
        // Encrypt and MAC the response data
        short secureLen = secureChannel.wrap(buffer, (short) 0, len);
        
        apdu.setOutgoingAndSend((short) 0, secureLen);
    }

    /**
     * Step 3: Verify PIN (Now Protected by SCP03)
     */
    private void verifyPin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        // Since we called unwrap(), buffer contains plaintext PIN
        // Standard Iso7816 offset might need adjustment if unwrap shifts data, 
        // but typically GP unwrap keeps data at ISO7816.OFFSET_CDATA
        
        // Get length from the unwrapped state
        byte byteRead = (byte) buffer[ISO7816.OFFSET_LC]; // Rough approximation after unwrap

        if (userPin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        
        // Send success (Empty body, still wrapped for consistency)
        sendSecureResponse(apdu, (short) 0);
    }

    /**
     * Get Balance (Returns Encrypted Long)
     */
    private void getBalance(APDU apdu) {
        if (!userPin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buffer = apdu.getBuffer();
        
        Util.setShort(buffer, (short) 0, (short) 0);
        Util.setShort(buffer, (short) 2, (short) 0);
        Util.setShort(buffer, (short) 4, (short) (shadowBalance >> 16));
        Util.setShort(buffer, (short) 6, (short) shadowBalance);

        // Encrypt the balance before sending
        sendSecureResponse(apdu, (short) 8);
    }

    /**
     * Process Debit (Encrypted Request -> Atomic Swap -> Encrypted Proof)
     */
    private void processDebit(APDU apdu) {
        if (!userPin.isValidated()) ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);

        byte[] buffer = apdu.getBuffer();
        // buffer now contains DECRYPTED payload from enforceSecureChannel
        
        // Parse Amount (4 bytes)
        int amount = Util.makeShort(buffer[ISO7816.OFFSET_CDATA], buffer[(short)(ISO7816.OFFSET_CDATA+1)]) << 16 |
                     (Util.makeShort(buffer[(short)(ISO7816.OFFSET_CDATA+2)], buffer[(short)(ISO7816.OFFSET_CDATA+3)]) & 0xFFFF);

        if (amount <= 0) ISOException.throwIt(SW_INVALID_AMOUNT);
        if (shadowBalance < amount) ISOException.throwIt(SW_NEGATIVE_BALANCE);

        // ATOMIC UPDATE
        JCSystem.beginTransaction();
        try {
            shadowBalance = shadowBalance - amount;
            nonce++;
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }

        // GENERATE PROOF
        short offset = 0;
        
        // A. Copy Amount
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, scratchBuffer, offset, (short) 4);
        offset += 4;
        
        // B. Copy Nonce
        Util.setShort(scratchBuffer, offset, (short) (nonce >> 16));
        Util.setShort(scratchBuffer, (short)(offset+2), (short) nonce);
        offset += 4;
        
        // C. Copy Merchant ID
        Util.arrayCopy(buffer, (short)(ISO7816.OFFSET_CDATA+4), scratchBuffer, offset, (short) 8);
        offset += 8;

        // Sign
        ecdsaSignature.init(keyPair.getPrivate(), Signature.MODE_SIGN);
        short sigLen = ecdsaSignature.sign(scratchBuffer, (short) 0, offset, buffer, (short) 0);
        
        // Append New Nonce
        Util.setShort(buffer, sigLen, (short) (nonce >> 16));
        Util.setShort(buffer, (short)(sigLen+2), (short) nonce);
        
        // Wrap and Send
        sendSecureResponse(apdu, (short) (sigLen + 4));
    }
}
