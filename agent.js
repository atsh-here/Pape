import express from "express";
import fs from "fs";
import Arweave from "arweave";
import { createData, ArweaveSigner } from "arbundles";
import { TurboFactory } from "@ardrive/turbo-sdk";
import { Readable } from "stream";

// --------------------------------------------------
// CONFIG
// --------------------------------------------------
const PORT = 8373;
const WALLET_FILE = "server-wallet.json";

// --------------------------------------------------
// APP
// --------------------------------------------------
const app = express();
app.use(express.json({ limit: "100mb" }));

// --------------------------------------------------
// ARWEAVE (wallet generation only)
// --------------------------------------------------
const arweave = Arweave.init({
  host: "arweave.net",
  port: 443,
  protocol: "https"
});

// --------------------------------------------------
// TURBO INITIALIZATION (SUBSIDIZED → PAID)
// --------------------------------------------------
let turbo;
let turboMode = "subsidized";

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  next();
});

if (fs.existsSync(WALLET_FILE)) {
  console.log("💰 Payment wallet found. Using PAID Turbo mode.");

  const wallet = JSON.parse(fs.readFileSync(WALLET_FILE, "utf-8"));
  turbo = TurboFactory.authenticated({ privateKey: wallet });
  turboMode = "paid";

} else {
  console.log("🆓 No wallet found. Using SUBSIDIZED Turbo mode.");

  // Turbo SDK allows unauthenticated uploads (subsidized / limited)
  turbo = TurboFactory.unauthenticated();
}

// --------------------------------------------------
// HELPER: Upload signed DataItem via Turbo
// --------------------------------------------------
async function uploadSignedDataItem(rawDataItem) {
  const result = await turbo.uploadSignedDataItem({
    dataItemStreamFactory: () => Readable.from(rawDataItem),
    dataItemSizeFactory: () => rawDataItem.length
  });

  return result.id;
}

// ==================================================
// POST /store/file
// ==================================================
app.post("/store/file", async (req, res) => {
  try {
    const { encryptedFile, contentType = "application/octet-stream" } = req.body;

    if (!encryptedFile) {
      return res.status(400).json({ error: "encryptedFile missing" });
    }

    console.log("🔐 FILE: signing & uploading");

    // 1. Ephemeral authorship wallet
    const jwk = await arweave.wallets.generate();
    const signer = new ArweaveSigner(jwk);

    // 2. Decode encrypted payload
    const dataBuffer = Buffer.from(encryptedFile, "utf-8");

    // 3. Create DataItem
    const dataItem = createData(dataBuffer, signer, {
      tags: [{ name: "Content-Type", value: contentType }]
    });

    // 4. Sign locally
    await dataItem.sign(signer);

    // 5. Upload via Turbo
    const fileTxId = await uploadSignedDataItem(dataItem.getRaw());

    console.log(`   ✅ FILE uploaded (${turboMode}): ${fileTxId}`);

    res.json({ fileTxId, mode: turboMode });

  } catch (err) {
    console.error("❌ /store/file failed:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ==================================================
// POST /store/map
// ==================================================
app.post("/store/map", async (req, res) => {
  try {
    const { indexKey, encryptedTxId } = req.body;

    if (!indexKey || !encryptedTxId) {
      return res.status(400).json({ error: "indexKey or encryptedTxId missing" });
    }

    console.log("🗺 MAP: signing & uploading");

    // 1. Fresh ephemeral wallet
    const jwk = await arweave.wallets.generate();
    const signer = new ArweaveSigner(jwk);

    // 2. Tag-only DataItem
    const dataItem = createData(Buffer.from(" "), signer, {
      tags: [
        { name: indexKey, value: encryptedTxId }
      ]
    });

    // 3. Sign
    await dataItem.sign(signer);

    // 4. Upload
    const mapTxId = await uploadSignedDataItem(dataItem.getRaw());

    console.log(`   ✅ MAP uploaded (${turboMode}): ${mapTxId}`);

    res.json({ mapTxId, mode: turboMode });

  } catch (err) {
    console.error("❌ /store/map failed:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// --------------------------------------------------
app.listen(PORT, () => {
  console.log(`🚀 Agent running at http://localhost:${PORT}`);
  console.log(`   Turbo mode: ${turboMode}`);
});
