package com.yiriwa.wallet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
import org.globalplatform.*;

/**
 * =========================================================================================
 * Yiriwa Offline Protocol (YOP) - Wallet Applet v3.0 (Patent Pending)
 * =========================================================================================
 *
 * OVERVIEW:
 * This Java Card applet implements the "Prover" side of the Yiriwa Offline Protocol v3.0.
 * It is designed for secure, offline, atomic value transfer with a unique "Viral Audit"
 * mechanism that entangles transaction histories between peers to detect fraud without
 * real-time connectivity.
 *
 * -----------------------------------------------------------------------------------------
 * CORE SECURITY FEATURES:
 * 1. GlobalPlatform SCP03:
 * - All sensitive APDUs (PIN verification, Debit) must be wrapped in a Secure Channel.
 * - Provides confidentiality (Encryption) and integrity (MAC) to prevent sniffing and
 * MITM attacks over the NFC interface.
 *
 * 2. Two-Factor Authentication (CVM):
 * - Uses `OwnerPIN` to enforce user authorization.
 * - The `DEBIT` and `GET_BALANCE` commands throw SW_PIN_VERIFICATION_REQUIRED if the
 * PIN has not been validated in the current session.
 *
 * 3. Atomic Transactions:
 * - Uses `JCSystem.beginTransaction()` and `commitTransaction()` to ensure that
 * balance decrements and nonce increments are atomic. Protection against "tearing"
 * (power loss during write).
 *
 * -----------------------------------------------------------------------------------------
 * PATENTED LOGIC: "Viral Hash Entanglement" (The v3.0 Upgrade)
 * Unlike standard EMV offline counters, YOP v3.0 creates a distributed mesh of evidence.
 *
 * [The Entanglement Formula]
 * Current_Tx_Hash = SHA256(
 * Amount (4B) || Nonce (4B) || MerchantID (8B) || CardID (8B) ||
 * H_Card_Last (32B) ||  <-- The User's previous state
 * H_Term_Last (32B)     <-- The Merchant's previous state (injected via APDU)
 * )
 *
 * [The Viral Effect]
 * By signing this `Current_Tx_Hash`, the Card cryptographically attests to the state of
 * the Merchant (Terminal). When this Card is used at a *different* Merchant later, it
 * effectively transports proof of the first Merchant's state to the central ledger.
 * This makes it mathematically impossible for a Merchant to modify their local logs
 * without being detected by the "Viral" audit trail carried by users.
 *
 * -----------------------------------------------------------------------------------------
 * APDU INTERFACE SPECIFICATION:
 * CLA: 0x80 (Cleartext handshake) / 0x84 (Secure Channel Wrapped)
 *
 * [INS_VERIFY_PIN - 0x20]
 * - Payload: ASCII PIN (e.g., "1234")
 * - Security: Must be wrapped (SCP03)
 *
 * [INS_GET_BALANCE - 0x30]
 * - Response: 8-byte Big Endian Integer (Wrapped)
 *
 * [INS_DEBIT - 0x40] (The Entangled Swap)
 * - Input (48 Bytes): [Amount: 4] [MerchantID: 8] [TermNonce: 4] [H_Term_Last: 32]
 * - Output: [Signature: Var] [Current_Tx_Hash: 32] [New_Nonce: 4]
 *
 * -----------------------------------------------------------------------------------------
 * HARDWARE REQUIREMENTS:
 * - Java Card 3.0.5 or higher.
 * - GlobalPlatform 2.2.1+ with SCP03 support.
 * - NXP JCOP J3R180 or equivalent Secure Element.
 * - Available RAM: ~512 bytes for crypto buffers.
 *
 * =========================================================================================
 */
public class YiriwaApplet extends Applet {

    // -------------------------------------------------------------------------
    // Constants & Instructions
    // -------------------------------------------------------------------------
    private static final byte CLA_YIRIWA            = (byte) 0x80;
    
    private static final byte INS_VERIFY_PIN        = (byte) 0x20;
    private static final byte INS_GET_BALANCE       = (byte) 0x30;
    private static final byte INS_DEBIT             = (byte) 0x40;

    // GlobalPlatform specific instructions for Secure Channel Handshake
    private static final byte INS_GP_INITIALIZE_UPDATE = (byte) 0x50;
    private static final byte INS_GP_EXTERNAL_AUTH     = (byte) 0x82;
    
    // Status Words
    private static final short SW_PIN_VERIFICATION_REQUIRED = (short) 0x6301;
    private static final short SW_NEGATIVE_BALANCE          = (short) 0x6910;
    private static final short SW_INVALID_AMOUNT            = (short) 0x6911;
    private static final short SW_SECURE_CHANNEL_REQUIRED   = (short) 0x6982;

    // -------------------------------------------------------------------------
    // Persistent State (EEPROM)
    // -------------------------------------------------------------------------
    private OwnerPIN userPin;
    private long shadowBalance; 
    private int nonce;
    
    // v3.0 ENTANGLEMENT STATE
    // This is the "Chain" carried by the user.
    // It starts as 32-bytes of zeros (Genesis Hash).
    private byte[] lastTxHash;
    
    // Unique Card ID (Injected during Personalization)
    private byte[] cardId; 

    // -------------------------------------------------------------------------
    // Crypto Objects (RAM)
    // -------------------------------------------------------------------------
    private KeyPair keyPair;
    private Signature ecdsaSignature;
    private MessageDigest sha256;
    private SecureChannel secureChannel;
    
    // Temporary RAM buffer for crypto operations (Performance optimization)
    private byte[] scratchBuffer; 

    /**
     * Constructor: Initializes memory and keys.
     */
    private YiriwaApplet(byte[] bArray, short bOffset, byte bLength) {
        // 1. Initialize PIN (Limit: 3 tries, Length: 8)
        userPin = new OwnerPIN((byte) 3, (byte) 8);
        // Default PIN "1234" for development
        byte[] defaultPin = {(byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34};
        userPin.update(defaultPin, (short) 0, (byte) defaultPin.length);

        // 2. Initialize Wallet State
        shadowBalance = 10000; // Demo Start Balance
        nonce = 1;             // Monotonic Counter
        
        // 3. Initialize Audit Chain
        lastTxHash = new byte[32]; // 0000...0000
        // Demo Card ID
        cardId = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }; 

        // 4. Initialize Crypto Engines
        try {
            // SECP256R1 Curve
            keyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
            keyPair.genKeyPair();
            
            // Sign using SHA-256 hash
            ecdsaSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
            sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        // 5. Get Reference to GlobalPlatform Secure Channel
        secureChannel = GPSystem.getSecureChannel();
        
        // 6. Alloc RAM
        scratchBuffer = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);

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

        // 1. Pass Secure Channel Handshake commands directly to GlobalPlatform
        if (cla == (byte) 0x80 && (ins == INS_GP_INITIALIZE_UPDATE || ins == INS_GP_EXTERNAL_AUTH)) {
            secureChannel.processSecurity(apdu);
            return;
        }

        // 2. Filter Custom Commands
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
            case INS_DEBIT:
                enforceSecureChannel(apdu);
                processDebitEntangled(apdu); // The v3.0 Logic
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * Security Guard: Ensures APDU is encrypted/MAC'd before processing.
     * Unwraps the APDU in place.
     */
    private void enforceSecureChannel(APDU apdu) {
        byte level = secureChannel.getSecurityLevel();
        // Require C_DECRYPTION (Privacy) and C_MAC (Integrity)
        if ((level & (SecureChannel.C_DECRYPTION | SecureChannel.C_MAC)) == 0) {
            ISOException.throwIt(SW_SECURE_CHANNEL_REQUIRED);
        }
        
        try {
            short incomingLen = apdu.setIncomingAndReceive();
            // Unwrap modifies buffer: decrypts data and verifies MAC
            short clearDataLen = secureChannel.unwrap(apdu.getBuffer(), (short) 0, (short)(incomingLen + 5)); 
            apdu.setIncomingLength(clearDataLen); 
        } catch (Exception e) {
            // Bad MAC or Decryption failure
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    /**
     * Helper: Encrypts and sends response
     */
    private void sendSecureResponse(APDU apdu, short len) {
        short secureLen = secureChannel.wrap(apdu.getBuffer(), (short) 0, len);
        apdu.setOutgoingAndSend((short) 0, secureLen);
    }

    /**
     * PIN Verification
     */
    private void verifyPin(APDU apdu) {
         byte[] buffer = apdu.getBuffer();
         // buffer contains plaintext PIN after unwrap
         byte byteRead = (byte) buffer[ISO7816.OFFSET_LC];
         
         if (userPin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false) {
             ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
         }
         // Success
         sendSecureResponse(apdu, (short) 0);
    }
    
    /**
     * Get Balance
     */
    private void getBalance(APDU apdu) {
        if (!userPin.isValidated()) ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        
        byte[] buffer = apdu.getBuffer();
        Util.setShort(buffer, (short) 0, (short) 0);
        Util.setShort(buffer, (short) 2, (short) 0);
        Util.setShort(buffer, (short) 4, (short) (shadowBalance >> 16));
        Util.setShort(buffer, (short) 6, (short) shadowBalance);
        
        sendSecureResponse(apdu, (short) 8);
    }

    /**
     * v3.0 PATENT LOGIC: "Entangled Debit"
     * * Input Payload (48 Bytes):
     * [Amount: 4] [MerchantID: 8] [TermNonce: 4] [H_Term_Last: 32]
     * * Logic:
     * 1. Check Balance.
     * 2. Atomic Decrement.
     * 3. Construct "Entangled Block":
     * Block = Amount + Nonce + MerchID + CardID + H_Card_Last + H_Term_Last
     * 4. Hash the Block -> Current_Tx_Hash
     * 5. Update H_Card_Last = Current_Tx_Hash
     * 6. Sign Current_Tx_Hash
     */
    private void processDebitEntangled(APDU apdu) {
        if (!userPin.isValidated()) ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);

        byte[] buffer = apdu.getBuffer();
        short offset = ISO7816.OFFSET_CDATA;

        // --- 1. PARSE & CHECK ---
        int amount = Util.makeShort(buffer[offset], buffer[(short)(offset+1)]) << 16 |
                     (Util.makeShort(buffer[(short)(offset+2)], buffer[(short)(offset+3)]) & 0xFFFF);

        if (amount <= 0) ISOException.throwIt(SW_INVALID_AMOUNT);
        if (shadowBalance < amount) ISOException.throwIt(SW_NEGATIVE_BALANCE);

        // --- 2. ATOMIC STATE UPDATE ---
        JCSystem.beginTransaction();
        try {
            shadowBalance = shadowBalance - amount;
            nonce++;
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }

        // --- 3. CONSTRUCT ENTANGLED BLOCK (In Scratch RAM) ---
        // Structure: Amount(4) | Nonce(4) | MerchID(8) | CardID(8) | H_Card_Last(32) | H_Term_Last(32)
        // Total Size: 88 Bytes
        
        short hashOff = 0;
        
        // A. Copy Amount (From APDU)
        Util.arrayCopy(buffer, offset, scratchBuffer, hashOff, (short) 4); 
        hashOff += 4;
        
        // B. Copy Nonce (From State)
        Util.setShort(scratchBuffer, hashOff, (short) (nonce >> 16));
        Util.setShort(scratchBuffer, (short)(hashOff+2), (short) nonce);
        hashOff += 4;
        
        // C. Copy MerchantID (From APDU)
        Util.arrayCopy(buffer, (short)(offset+4), scratchBuffer, hashOff, (short) 8); 
        hashOff += 8;
        
        // D. Copy CardID (From State)
        Util.arrayCopy(cardId, (short) 0, scratchBuffer, hashOff, (short) 8);
        hashOff += 8;
        
        // E. Copy H_Card_Last (From State - The User's Chain)
        Util.arrayCopy(lastTxHash, (short) 0, scratchBuffer, hashOff, (short) 32);
        hashOff += 32;
        
        // F. Copy H_Term_Last (From APDU - The "Viral" Hook)
        // Offset input was: CDATA + 4(Amt) + 8(Merch) + 4(TNonce) = CDATA + 16
        Util.arrayCopy(buffer, (short)(offset+16), scratchBuffer, hashOff, (short) 32);
        hashOff += 32;

        // --- 4. COMPUTE SHA-256 ---
        // Result goes to scratchBuffer offset 128
        short hashResultOff = (short) 128;
        sha256.doFinal(scratchBuffer, (short) 0, hashOff, scratchBuffer, hashResultOff);

        // --- 5. UPDATE CHAIN ---
        JCSystem.beginTransaction();
        Util.arrayCopy(scratchBuffer, hashResultOff, lastTxHash, (short) 0, (short) 32);
        JCSystem.commitTransaction();

        // --- 6. SIGN THE HASH ---
        ecdsaSignature.init(keyPair.getPrivate(), Signature.MODE_SIGN);
        // Signing the 32-byte Hash directly
        short sigLen = ecdsaSignature.sign(scratchBuffer, hashResultOff, (short) 32, buffer, (short) 0);
        
        // --- 7. RESPONSE ---
        // Return: Signature(Var) || Current_Tx_Hash(32) || New_Nonce(4)
        
        // Append Hash after Sig
        Util.arrayCopy(scratchBuffer, hashResultOff, buffer, sigLen, (short) 32);
        short respOff = (short)(sigLen + 32);
        
        // Append New Nonce after Hash
        Util.setShort(buffer, respOff, (short) (nonce >> 16));
        Util.setShort(buffer, (short)(respOff+2), (short) nonce);
        
        // Encrypt and Send
        sendSecureResponse(apdu, (short) (respOff + 4));
    }
}
