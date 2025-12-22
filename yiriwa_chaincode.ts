import { Context, Contract, Info, Returns, Transaction } from 'fabric-contract-api';

/**
 * =========================================================================================
 * Yiriwa Offline Protocol (YOP) v5.2 - Settlement Chaincode
 * =========================================================================================
 * * UPDATES:
 * 1. Handles v5.2 Applet Payload (12 Bytes: 6 Data + 4 MAC + 2 Country ISO).
 * 2. Strips ISO Suffix before decompression.
 * 3. Archives Geography Data (Country ISO) for analytics.
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
    public rawBlob: string;       // Full 12 bytes (Hex)
    public macProof: string;      // 4 bytes (Integrity Check)
    public compressedData: string;// First 6 bytes
    public countryISO: string;    // Last 2 bytes (Geography)
    
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
        iso: string,
        mid: string, 
        amt: number, 
        item: number, 
        uploader: string
    ) {
        this.rawBlob = fullBlob;
        this.macProof = mac;
        this.compressedData = data;
        this.countryISO = iso;
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
     * Expects 12 Bytes (24 Hex Chars):
     * [Data: 6B] [MAC: 4B] [ISO: 2B]
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
        if (wallet.balance < currentTxAmount) {
            throw new Error(`Insufficient ledger balance. Wallet: ${wallet.balance}, Tx: ${currentTxAmount}`);
        }
        wallet.balance -= currentTxAmount;
        wallet.lastUpdated = new Date().toISOString();

        // 3. Process Harvested Blob (Merchant A's History)
        let auditLogMsg = "No previous log harvested.";
        
        // Check for Genesis/Empty state (24 zeros) or null
        const isGenesis = !harvestedBlobHex || harvestedBlobHex === "000000000000000000000000" || harvestedBlobHex === "";
        
        if (!isGenesis) {
            // v5.2 Expectation: 12 Bytes = 24 Hex Chars
            if (harvestedBlobHex.length !== 24) {
                throw new Error(`Invalid Blob Size. Expected 12 bytes (24 hex chars), got ${harvestedBlobHex.length}`);
            }

            // A. Parse Blob Structure
            // [Data: 12 chars] [MAC: 8 chars] [ISO: 4 chars]
            const dataPart = harvestedBlobHex.substring(0, 12);
            const macPart = harvestedBlobHex.substring(12, 20);
            const isoPart = harvestedBlobHex.substring(20, 24); // The Suffix

            // B. Decompress Data (On-Chain Logic)
            const context = this.decompressBlob(dataPart);

            // C. Create Audit Record
            const logId = `AUDIT_${cardId}_${ctx.stub.getTxID()}`;
            const auditRecord = new HarvestedAuditLog(
                harvestedBlobHex,
                macPart,
                dataPart,
                isoPart, // Store the ISO
                context.mid,
                context.amount,
                context.item,
                ctx.clientIdentity.getID()
            );

            // D. Store Audit Log
            await ctx.stub.putState(logId, Buffer.from(JSON.stringify(auditRecord)));
            
            // E. Emit Recovery Event
            const event = { 
                type: "HISTORY_RECOVERED",
                cardId: cardId,
                recoveredContext: context,
                countryISO: isoPart, // Include geography in event
                integrityProof: macPart
            };
            ctx.stub.setEvent('AuditLogRecovered', Buffer.from(JSON.stringify(event)));
            
            auditLogMsg = `Restored history from Merchant ${context.mid} ($${context.amount}) in Region ${isoPart}`;
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
