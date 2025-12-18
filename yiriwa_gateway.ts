import * as express from 'express';
import { Gateway, Wallets } from 'fabric-network';
import * as path from 'path';
import * as fs from 'fs';

/**
 * =========================================================================================
 * Yiriwa Gateway v5.1 (Dumb Pipe)
 * =========================================================================================
 * * UPDATES:
 * 1. Accepts "Dumb" Hex Blobs (20 chars / 10 bytes) from Android POS.
 * 2. No local processing/validation of blobs.
 * 3. Forwards directly to Chaincode 'SettleWithHarvest' for decompression.
 */

const app = express();
app.use(express.json());

const PORT = 3000;
const CHANNEL_NAME = 'yiriwa-channel';
const CHAINCODE_NAME = 'yiriwa-cc';
const MERCHANT_USER = 'merchantB_admin'; 

// --- Fabric Connection Helper ---
async function connectToNetwork(userId: string) {
    const ccpPath = path.resolve(__dirname, '..', 'connection-org1.json');
    const ccp = JSON.parse(fs.readFileSync(ccpPath, 'utf8'));
    const walletPath = path.join(process.cwd(), 'wallet');
    const wallet = await Wallets.newFileSystemWallet(walletPath);

    const identity = await wallet.get(userId);
    if (!identity) {
        throw new Error(`Identity "${userId}" not found in wallet`);
    }

    const gateway = new Gateway();
    await gateway.connect(ccp, { 
        wallet, 
        identity: userId, 
        discovery: { enabled: true, asLocalhost: true } 
    });

    const network = await gateway.getNetwork(CHANNEL_NAME);
    const contract = network.getContract(CHAINCODE_NAME);

    return { gateway, contract };
}

/**
 * Endpoint: /api/v1/sync/batch
 * Payload: { 
 * merchantId: "9xB2", 
 * transactions: [ 
 * { cardId: "12345678", amount: 120, harvestedBlob: "AABBCCDDEEFF00112233" } 
 * ] 
 * }
 */
app.post('/api/v1/sync/batch', async (req, res) => {
    const { merchantId, transactions } = req.body;
    
    if (!transactions || !Array.isArray(transactions)) {
        return res.status(400).json({ error: 'Invalid batch format' });
    }

    console.log(`[Sync] Batch from Merchant ${merchantId}: ${transactions.length} items`);

    let successCount = 0;
    let failCount = 0;
    let errors = [];

    let gateway;
    try {
        const networkObj = await connectToNetwork(MERCHANT_USER);
        const contract = networkObj.contract;
        gateway = networkObj.gateway;

        for (const tx of transactions) {
            try {
                // v5.1 Protocol: 
                // The POS sends us a 20-char Hex String (10 bytes).
                // We pass it blindly to the chaincode.
                
                const blobArg = tx.harvestedBlob || "";
                
                // Logging for debug
                if (blobArg.length === 20) {
                    console.log(`[Tx] Card ${tx.cardId}: Settling $${tx.amount} + Archiving History (10B Blob)`);
                } else {
                    console.log(`[Tx] Card ${tx.cardId}: Settling $${tx.amount} (Genesis/Empty Blob)`);
                }

                // Chaincode: SettleWithHarvest(ctx, cardId, currentTxAmount, harvestedBlobHex)
                const resultBuffer = await contract.submitTransaction(
                    'SettleWithHarvest',
                    tx.cardId,
                    tx.amount.toString(),
                    blobArg
                );
                
                successCount++;
            } catch (err) {
                console.error(`   -> Failed: ${err.message}`);
                failCount++;
                errors.push({ cardId: tx.cardId, error: err.message });
            }
        }
    } catch (err) {
        console.error('Fabric Network Error:', err);
        return res.status(500).json({ error: 'Ledger Gateway Unavailable' });
    } finally {
        if (gateway) {
            gateway.disconnect();
        }
    }

    res.json({
        status: 'Batch Processed',
        total: transactions.length,
        settled: successCount,
        rejected: failCount,
        errors: errors
    });
});

app.listen(PORT, () => {
    console.log(`Yiriwa Gateway v5.1 running on http://localhost:${PORT}`);
});
