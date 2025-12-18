import { Context, Contract, Info, Returns, Transaction } from 'fabric-contract-api';

/**
 * =========================================================================================
 * Yiriwa Offline Protocol (YOP) v5.1 - Settlement Chaincode
 * =========================================================================================
 * * UPDATES:
 * 1. Handles v5.1 Applet Payload (10 Bytes: 6 Data + 4 MAC).
 * 2. Performs On-Chain Decompression (POS is now "dumb").
 * 3. Archives the MAC Proof for dispute resolution.
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
    public rawBlob: string;       // Full 10 bytes (Hex)
    public macProof: string;      // Last 4 bytes (Integrity Check)
    public compressedData: string;// First 6 bytes
    
    // Decompressed Context
    public merchantId: string;
    public amount: number;
    public itemId: number;
    
    public uploadedBy: string; 
    public timestamp: string;

    constructor(
        fullBlob: string, 
        mac: string, 
        data: string, 
        mid: string, 
        amt: number, 
        item: number, 
        uploader: string
    ) {
        this.rawBlob = fullBlob;
        this.macProof = mac;
        this.compressedData = data;
        this.merchantId = mid;
        this.amount = amt;
        this.itemId = item;
        this.uploadedBy = uploader;
        this.timestamp = new Date().toISOString();
    }
}

@Info({title: 'YiriwaOfflineContract', description: 'Decompression & Settlement for ZK-Carrier Protocol'})
export class YiriwaContract extends Contract {

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
     * splits it (Data vs MAC), decompresses the Data, and archives the MAC.
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
        if (wallet.balance < currentTxAmount) {
            throw new Error(`Insufficient ledger balance. Wallet: ${wallet.balance}, Tx: ${currentTxAmount}`);
        }
        wallet.balance -= currentTxAmount;
        wallet.lastUpdated = new Date().toISOString();

        // 3. Process Harvested Blob (Merchant A's History)
        let auditLogMsg = "No previous log harvested.";
        
        // Check for Genesis/Empty state (20 zeros) or null
        const isGenesis = !harvestedBlobHex || harvestedBlobHex === "00000000000000000000" || harvestedBlobHex === "";
        
        if (!isGenesis) {
            // v5.1 Expectation: 10 Bytes = 20 Hex Chars
            if (harvestedBlobHex.length !== 20) {
                throw new Error(`Invalid Blob Size. Expected 10 bytes (20 hex chars), got ${harvestedBlobHex.length}`);
            }

            // A. Parse Blob Structure
            // [Data: 6 Bytes (12 chars)] + [MAC: 4 Bytes (8 chars)]
            const dataPart = harvestedBlobHex.substring(0, 12);
            const macPart = harvestedBlobHex.substring(12, 20);

            // B. Decompress Data (On-Chain Logic)
            const context = this.decompressBlob(dataPart);

            // C. Create Audit Record
            const logId = `AUDIT_${cardId}_${ctx.stub.getTxID()}`;
            const auditRecord = new HarvestedAuditLog(
                harvestedBlobHex,
                macPart,
                dataPart,
                context.mid,
                context.amount,
                context.item,
                ctx.clientIdentity.getID() // The Merchant B who uploaded it
            );

            // D. Store Audit Log
            await ctx.stub.putState(logId, Buffer.from(JSON.stringify(auditRecord)));
            
            // E. Emit Recovery Event
            const event = { 
                type: "HISTORY_RECOVERED",
                cardId: cardId,
                recoveredContext: context,
                integrityProof: macPart
            };
            ctx.stub.setEvent('AuditLogRecovered', Buffer.from(JSON.stringify(event)));
            
            auditLogMsg = `Restored history from Merchant ${context.mid} ($${context.amount})`;
        }

        // 4. Commit Wallet State
        await ctx.stub.putState(cardId, Buffer.from(JSON.stringify(wallet)));

        // 5. Return Summary
        const result = { 
            cardId, 
            newBalance: wallet.balance, 
            status: "SETTLED",
            auditResult: auditLogMsg
        };

        return JSON.stringify(result);
    }

    /**
     * Helper: Decompression Engine
     * Reverses the v5.1 Applet's "multiply24BitBy62AndAdd" logic
     */
    private decompressBlob(hex6Bytes: string): { mid: string, amount: number, item: number } {
        const buffer = Buffer.from(hex6Bytes, 'hex');

        // 1. Extract Merchant ID Integer (Bytes 0-2) -> 24-bit Integer
        const midInt = (buffer[0] << 16) | (buffer[1] << 8) | buffer[2];
        
        // 2. Extract Amount (Bytes 3-4) -> 16-bit Integer
        const amount = (buffer[3] << 8) | buffer[4];

        // 3. Extract Item ID (Byte 5)
        const item = buffer[5];

        // 4. Decode Base62 (Integer -> String)
        // val = c0*62^3 + c1*62^2 + c2*62^1 + c3
        let tempVal = midInt;
        let power = 238328; // 62^3
        let midString = "";

        // Note: JS numbers are 64-bit float, so 24-bit bitwise logic is safe
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
