import { Context, Contract, Info, Returns, Transaction } from 'fabric-contract-api';

/**
 * =========================================================================================
 * Yiriwa Offline Protocol (YOP) v7.0 - Batch Settlement Chaincode
 * =========================================================================================
 * * CORE LOGIC:
 * 1. PARSE: Extracts Wallet ID (Header) + List of Logs (Body).
 * 2. VERIFY: Checks that Blob Identity matches Wallet Identity.
 * 3. DEDUPLICATE: Checks Ledger for existing Tx IDs (Idempotency).
 * 4. SETTLE: Debits the *current* online transaction + Archives *offline* history.
 */

// --- Data Models ---

class UserWallet {
    public docType: string = 'wallet';
    public walletId: string; // Hex String (e.g., "1A2B3C4D")
    public balance: number;
    public lastUpdated: string;

    constructor(walletId: string, initialBalance: number) {
        this.walletId = walletId;
        this.balance = initialBalance;
        this.lastUpdated = new Date().toISOString();
    }
}

class AuditLog {
    public docType: string = 'audit_log';
    public compositeKey: string; // Unique ID (Wallet + TxCode)
    
    // Decompressed Data
    public merchantId: string;
    public amount: number;
    public itemId: number;
    public countryISO: string;
    
    // Security
    public macProof: string;
    public rawData: string;
    public uploadedBy: string; 
    public timestamp: string;

    constructor(
        key: string,
        mid: string, 
        amt: number, 
        item: number, 
        iso: string,
        mac: string,
        raw: string,
        uploader: string
    ) {
        this.compositeKey = key;
        this.merchantId = mid;
        this.amount = amt;
        this.itemId = item;
        this.countryISO = iso;
        this.macProof = mac;
        this.rawData = raw;
        this.uploadedBy = uploader;
        this.timestamp = new Date().toISOString();
    }
}

@Info({title: 'YiriwaContractV7', description: 'Batch Settlement & Idempotency Engine'})
export class YiriwaContract extends Contract {

    private static BASE62_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    @Transaction()
    public async InitLedger(ctx: Context): Promise<void> {
        // Initialize a Demo Wallet with ID "1A2B3C4D" (Matches simulation)
        const demoId = '1A2B3C4D';
        const wallet = new UserWallet(demoId, 5000); // $50.00
        await ctx.stub.putState(demoId, Buffer.from(JSON.stringify(wallet)));
        console.info(`v7 Ledger Initialized: Wallet ${demoId} created.`);
    }

    /**
     * SettleBatch (v7.0)
     * ---------------------------------------------------------
     * Payload Structure:
     * [WalletID (8 Hex Chars)] + [Log 1 (24 Hex)] + [Log 2 (24 Hex)] ...
     */
    @Transaction()
    public async SettleBatch(
        ctx: Context, 
        walletIdArg: string, // The ID claimed by the POS
        currentTxAmount: number, 
        fullBlobHex: string
    ): Promise<string> {
        
        // 1. Validate Input
        if (!fullBlobHex || fullBlobHex.length < 8) {
            throw new Error("Invalid Blob: Too short to contain Header.");
        }

        // 2. Identity Verification (Header Check)
        // Extract Header (First 4 Bytes = 8 Hex Chars)
        const headerWalletId = fullBlobHex.substring(0, 8).toUpperCase();
        
        // Ensure the blob belongs to the wallet being debited
        if (headerWalletId !== walletIdArg.toUpperCase()) {
            throw new Error(`Identity Mismatch: Blob belongs to ${headerWalletId}, but Tx is for ${walletIdArg}`);
        }

        // 3. Fetch & Update Wallet Balance (Online Tx)
        const walletData = await ctx.stub.getState(headerWalletId);
        if (!walletData || walletData.length === 0) {
            throw new Error(`Wallet ${headerWalletId} not found`);
        }
        const wallet: UserWallet = JSON.parse(walletData.toString());

        if (wallet.balance < currentTxAmount) {
            throw new Error(`Insufficient Funds: Balance ${wallet.balance} < ${currentTxAmount}`);
        }
        
        // Apply Debit
        wallet.balance -= currentTxAmount;
        wallet.lastUpdated = new Date().toISOString();
        await ctx.stub.putState(headerWalletId, Buffer.from(JSON.stringify(wallet)));

        // 4. Batch Processing Loop (The "Zipper")
        const logsBlob = fullBlobHex.substring(8); // Strip Header
        const LOG_LENGTH = 24; // 12 Bytes * 2 Hex Chars
        
        let processedCount = 0;
        let skippedCount = 0;
        let totalAmountRecovered = 0;

        // Loop through chunks of 24 characters
        for (let i = 0; i < logsBlob.length; i += LOG_LENGTH) {
            const chunk = logsBlob.substring(i, i + LOG_LENGTH);
            if (chunk.length !== LOG_LENGTH) break; // Ignore malformed/trailing bits

            // A. Parse Log Parts
            const dataHex = chunk.substring(0, 12); // Compressed Data
            const macHex  = chunk.substring(12, 20); // MAC
            const isoHex  = chunk.substring(20, 24); // Country ISO

            // B. Decompress
            const txContext = this.decompressLog(dataHex);
            
            // C. Generate Composite Key (Idempotency ID)
            // Key = WalletID + RawDataHex (The compressed data is unique per tx due to timestamp)
            const uniqueLogKey = `LOG_${headerWalletId}_${dataHex}`;

            

            // D. Idempotency Check (The "Existence Proof")
            const existingLog = await ctx.stub.getState(uniqueLogKey);
            
            if (existingLog && existingLog.length > 0) {
                // DUPLICATE DETECTED
                skippedCount++;
                continue; // Skip this log, do not double count
            }

            // E. New Record -> Archive It
            const newLog = new AuditLog(
                uniqueLogKey,
                txContext.mid,
                txContext.amount,
                txContext.item,
                isoHex,
                macHex,
                chunk,
                ctx.clientIdentity.getID()
            );

            await ctx.stub.putState(uniqueLogKey, Buffer.from(JSON.stringify(newLog)));
            
            processedCount++;
            totalAmountRecovered += txContext.amount;
        }

        // 5. Emit Event & Return
        const eventPayload = {
            walletId: headerWalletId,
            newLogs: processedCount,
            duplicates: skippedCount,
            valueRecovered: totalAmountRecovered
        };
        ctx.stub.setEvent('BatchSettled', Buffer.from(JSON.stringify(eventPayload)));

        return JSON.stringify({
            status: "SUCCESS",
            wallet: headerWalletId,
            newBalance: wallet.balance,
            batchReport: {
                processed: processedCount,
                skipped: skippedCount,
                recoveredValue: totalAmountRecovered
            }
        });
    }

    /**
     * Helper: Decompression Logic (Base62 Reverse Map)
     */
    private decompressLog(hex6Bytes: string): { mid: string, amount: number, item: number } {
        const buffer = Buffer.from(hex6Bytes, 'hex');

        // Bytes 0-2: Merchant ID Int
        const midInt = (buffer[0] << 16) | (buffer[1] << 8) | buffer[2];
        // Bytes 3-4: Amount
        const amount = (buffer[3] << 8) | buffer[4];
        // Byte 5: Item ID
        const item = buffer[5];

        // Base62 Decode
        let tempVal = midInt;
        let power = 238328; 
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
    public async GetWallet(ctx: Context, walletId: string): Promise<string> {
        const data = await ctx.stub.getState(walletId);
        return data ? data.toString() : "{}";
    }
}
