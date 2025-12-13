// This is the Node.js/Express Middleware that sits between the Android App and the Hyperledger Network. When the merchant comes back online, their phone will POST the offline transaction blobs to this API, which then uses the fabric-network SDK to invoke the chaincode.

import * as express from 'express';
import { Gateway, Wallets } from 'fabric-network';
import * as path from 'path';
import * as fs from 'fs';

/**
 * Yiriwa Offline Protocol (YOP) - Merchant Sync Gateway
 * * This API receives the offline transaction blobs from the Android Terminal
 * * and submits them to the Hyperledger Fabric blockchain for settlement.
 */

const app = express();
app.use(express.json());

const PORT = 3000;
const CHANNEL_NAME = 'yiriwa-channel';
const CHAINCODE_NAME = 'yiriwa-cc';
const MSP_ID = 'Org1MSP'; // Example Organization

// Helper to connect to Fabric
async function connectToNetwork(userId: string) {
    // Load connection profile (defined in your Fabric network setup)
    const ccpPath = path.resolve(__dirname, '..', 'connection-org1.json');
    const ccp = JSON.parse(fs.readFileSync(ccpPath, 'utf8'));

    // Create a new file system based wallet for managing identities.
    const walletPath = path.join(process.cwd(), 'wallet');
    const wallet = await Wallets.newFileSystemWallet(walletPath);

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
 * Receives an array of offline transactions from the Android SoftPOS
 */
app.post('/api/v1/sync/batch', async (req, res) => {
    const { merchantId, transactions } = req.body;
    
    if (!transactions || !Array.isArray(transactions)) {
        return res.status(400).json({ error: 'Invalid batch format' });
    }

    console.log(`Received batch from Merchant ${merchantId}: ${transactions.length} txs`);

    let successCount = 0;
    let failCount = 0;
    let errors = [];

    // Connect to Fabric (Assuming merchant identity is 'admin' for this demo)
    let gateway;
    try {
        const networkObj = await connectToNetwork('admin');
        const contract = networkObj.contract;
        gateway = networkObj.gateway;

        // Process transactions sequentially
        // In production, you might parallelize this or use a queue
        for (const tx of transactions) {
            try {
                // Submit Transaction to Chaincode
                // Args: cardId, merchantId, amount, nonce, signatureHex
                console.log(`Processing Tx for Card: ${tx.cardId} Nonce: ${tx.nonce}`);
                
                await contract.submitTransaction(
                    'ProcessOfflineTransaction',
                    tx.cardId,
                    merchantId,
                    tx.amount.toString(),
                    tx.nonce.toString(),
                    tx.signatureHex
                );

                successCount++;
            } catch (err) {
                console.error(`Tx Failed: ${err.message}`);
                failCount++;
                errors.push({ cardId: tx.cardId, nonce: tx.nonce, error: err.message });
            }
        }
    } catch (err) {
        console.error('Fabric Connection Error:', err);
        return res.status(500).json({ error: 'Blockchain Network Unavailable' });
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
 * Debug endpoint to check status
 */
app.get('/api/v1/wallet/:cardId', async (req, res) => {
    try {
        const { gateway, contract } = await connectToNetwork('admin');
        const result = await contract.evaluateTransaction('GetWallet', req.params.cardId);
        gateway.disconnect();
        
        res.json(JSON.parse(result.toString()));
    } catch (err) {
        res.status(404).json({ error: err.message });
    }
});

app.listen(PORT, () => {
    console.log(`Yiriwa Gateway running on http://localhost:${PORT}`);
});
