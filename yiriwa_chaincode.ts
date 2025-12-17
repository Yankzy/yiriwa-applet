import { Context, Contract, Info, Returns, Transaction } from 'fabric-contract-api';
import * as crypto from 'crypto';

/**
 * =========================================================================================
 * Yiriwa Offline Protocol (YOP) v4.1 - Settlement Chaincode
 * =========================================================================================
 * FEATURES:
 * 1. Validates & Settles current offline transactions (Merchant B).
 * 2. Decompresses & Archives historical logs carried by the user (Merchant A).
 * 3. Implements the Server-Side Expansion of the "Applet Compression" schema.
 */

// --- Data Models ---

class UserWallet {
    public docType: string = 'wallet';
    public cardId: string;
    public balance: number;
    public lastUpdated: string;

    constructor(cardId: string, initialBalance: number) {
        this.cardId = cardId;
        this.balance = initialBalance;
        this.lastUpdated = new Date().toISOString();
    }
}

class HarvestedAuditLog {
    public docType: string = 'audit_log';
    public sourceBlob: string; // The 6-byte hex
    public decodedMerchantId: string;
    public decodedAmount: number;
    public decodedItem: number;
    public uploadedBy: string; // Merchant B (The Carrier's destination)
    public timestamp: string;

    constructor(blob: string, mid: string, amt: number, item: number, uploader: string) {
        this.sourceBlob = blob;
        this.decodedMerchantId = mid;
        this.decodedAmount = amt;
        this.decodedItem = item;
        this.uploadedBy = uploader;
        this.timestamp = new Date().toISOString();
    }
}

@Info({title: 'YiriwaOfflineContract', description: 'Decompression & Settlement for ZK-Carrier Protocol'})
export class YiriwaContract extends Contract {

    // Base62 Alphabet (Must match Applet & Android Client)
    private static BASE62_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    @Transaction()
    public async InitLedger(ctx: Context): Promise<void> {
        const demoCardId = '12345678';
        const wallet = new UserWallet(demoCardId, 10000);
        await ctx.stub.putState(demoCardId, Buffer.from(JSON.stringify(wallet)));
        console.info(`Wallet ${demoCardId} initialized`);
    }

    /**
     * SettleWithHarvest (The Core Logic)
     * ---------------------------------------------------------
     * This function is called by Merchant B.
     * 1. Debits the user for the CURRENT transaction (Merchant B's Sale).
     * 2. Takes the 'harvestedBlob' (from Merchant A) found on the card,
     * decompresses it, and writes it to the permanent ledger history.
     */
    @Transaction()
    public async SettleWithHarvest(
        ctx: Context, 
        cardId: string, 
        currentTxAmount: number, 
        harvestedBlobHex: string
    ): Promise<string> {
        
        // 1. Fetch Wallet
        const walletData = await ctx.stub.getState(cardId);
        if (!walletData || walletData.length === 0) {
            throw new Error(`Wallet ${cardId} does not exist`);
        }
        const wallet: UserWallet = JSON.parse(walletData.toString());

        // 2. Process Current Debit (Merchant B)
        // Trust Assumption: The Merchant Peer calling this is authenticated via Fabric MSP
        // and has verified the Card's SCP03 MAC off-chain.
        if (wallet.balance < currentTxAmount) {
            throw new Error(`Insufficient ledger balance. Wallet: ${wallet.balance}, Tx: ${currentTxAmount}`);
        }
        wallet.balance -= currentTxAmount;
        wallet.lastUpdated = new Date().toISOString();

        // 3. Process Harvested Blob (Merchant A's History)
        let auditLogMsg = "No previous log harvested.";
        
        if (harvestedBlobHex && harvestedBlobHex.length === 12) { // 6 bytes = 12 hex chars
            // A. Decompress
            const expandedData = this.decompressBlob(harvestedBlobHex);
            
            // B. Create Audit Record
            // We key this by the content hash or timestamp to avoid collisions
            const logId = `AUDIT_${cardId}_${ctx.stub.getTxID()}`;
            const auditRecord = new HarvestedAuditLog(
                harvestedBlobHex,
                expandedData.mid,
                expandedData.amount,
                expandedData.item,
                ctx.clientIdentity.getID() // The Merchant B who uploaded it
            );

            // C. Store Audit Log
            await ctx.stub.putState(logId, Buffer.from(JSON.stringify(auditRecord)));
            auditLogMsg = `Restored history from Merchant ${expandedData.mid} ($${expandedData.amount})`;
        } else if (harvestedBlobHex && harvestedBlobHex !== "000000000000") {
             // Basic validation for "empty" cards
             throw new Error("Invalid Blob Format. Must be 12 Hex chars (6 bytes).");
        }

        // 4. Commit Wallet State
        await ctx.stub.putState(cardId, Buffer.from(JSON.stringify(wallet)));

        // 5. Emit Event
        const event = { cardId, newBalance: wallet.balance, auditLog: auditLogMsg };
        ctx.stub.setEvent('TxSettled', Buffer.from(JSON.stringify(event)));

        return JSON.stringify(event);
    }

    /**
     * Helper: Decompression Engine
     * Reverses the Applet's "compressAndPack" logic.
     */
    private decompressBlob(hex: string): { mid: string, amount: number, item: number } {
        const buffer = Buffer.from(hex, 'hex');

        // 1. Extract Merchant ID Integer (Bytes 0-2)
        // 24-bit Integer
        const midInt = (buffer[0] << 16) | (buffer[1] << 8) | buffer[2];
        
        // 2. Extract Amount (Bytes 3-4)
        // 16-bit Integer
        const amount = (buffer[3] << 8) | buffer[4];

        // 3. Extract Item ID (Byte 5)
        const item = buffer[5];

        // 4. Decode Base62 (Integer -> String)
        // val = c0*62^3 + c1*62^2 + c2*62^1 + c3
        let tempVal = midInt;
        let power = 238328; // 62^3
        let midString = "";

        for (let i = 0; i < 4; i++) {
            const index = Math.floor(tempVal / power);
            midString += YiriwaContract.BASE62_CHARS.charAt(index);
            
            tempVal = tempVal % power;
            power = Math.floor(power / 62);
        }

        return { mid: midString, amount, item };
    }

    @Transaction(false)
    @Returns('string')
    public async GetWallet(ctx: Context, cardId: string): Promise<string> {
        const data = await ctx.stub.getState(cardId);
        return data ? data.toString() : "{}";
    }
}
