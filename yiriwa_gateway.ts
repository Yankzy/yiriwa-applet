import * as express from 'express';
import { Gateway, Wallets } from 'fabric-network';
import * as path from 'path';
import * as fs from 'fs';

/**
 * =========================================================================================
 * Yiriwa Offline Protocol (YOP) v4.1 - Merchant Sync Gateway
 * =========================================================================================
 * * Acts as the bridge between Android SoftPOS and Hyperledger Fabric.
 * * HANDLES:
 * 1. Batch receiving of offline transactions.
 * 2. Invoking the 'SettleWithHarvest' chaincode function.
 * 3. Managing Merchant MSP Identities (Wallets).
 */

const app = express();
app.use(express.json());

const PORT = 3000;
const CHANNEL_NAME = 'yiriwa-channel';
const CHAINCODE_NAME = 'yiriwa-cc';
// In production, this comes from the authenticated Merchant's JWT or API Key
const MERCHANT_USER = 'merchantB_admin'; 

// Helper to connect to Fabric
async function connectToNetwork(userId: string) {
    // Load connection profile
    const ccpPath = path.resolve(__dirname, '..', 'connection-org1.json');
    const ccp = JSON.parse(fs.readFileSync(ccpPath, 'utf8'));

    // Create a new file system based wallet for managing identities.
    const walletPath = path.join(process.cwd(), 'wallet');
    const wallet = await Wallets.newFileSystemWallet(walletPath);

    // Check if user exists
    const identity = await wallet.get(userId);
    if (!identity) {
        throw new Error(`An identity for the user "${userId}" does not exist in the wallet`);
    }

    // Create a new gateway for connecting to our peer node.
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
 * { cardId: "12345678", amount: 120, harvestedBlob: "0000..." } 
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
        // Connect as the Merchant (or Admin acting for them)
        const networkObj = await connectToNetwork(MERCHANT_USER);
        const contract = networkObj.contract;
        gateway = networkObj.gateway;

        for (const tx of transactions) {
            try {
                // v4.1 Protocol: SettleWithHarvest
                // We submit the CURRENT transaction details + the PREVIOUS blob found on card.
                console.log(`[Tx] Settle Card: ${tx.cardId} ($${tx.amount}) + Harvest: ${tx.harvestedBlob || "None"}`);
                
                // Chaincode Args: SettleWithHarvest(ctx, cardId, currentTxAmount, harvestedBlobHex)
                // Note: harvestedBlob must be a hex string. If null, send empty string.
                const blobArg = tx.harvestedBlob || "";

                const resultBuffer = await contract.submitTransaction(
                    'SettleWithHarvest',
                    tx.cardId,
                    tx.amount.toString(),
                    blobArg
                );
                
                const resultJson = JSON.parse(resultBuffer.toString());
                // Optional: Log the decompressed history returned by the chaincode event
                if (resultJson.auditLog) {
                    console.log(`   -> Ledger Archived: ${resultJson.auditLog}`);
                }

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

/**
 * Endpoint: /api/v1/wallet/:cardId
 */
app.get('/api/v1/wallet/:cardId', async (req, res) => {
    try {
        const { gateway, contract } = await connectToNetwork(MERCHANT_USER);
        const result = await contract.evaluateTransaction('GetWallet', req.params.cardId);
        gateway.disconnect();
        
        res.json(JSON.parse(result.toString()));
    } catch (err) {
        res.status(404).json({ error: err.message });
    }
});

app.listen(PORT, () => {
    console.log(`Yiriwa Gateway v4.1 running on http://localhost:${PORT}`);
});
