const AGENT_BASE = "http://localhost:8373";

// =====================================================
// Volatile session state (never persisted)
// =====================================================
let unlocked = false;
let sessionPassword = null;
let mnemonicKey = null;
let indexRootKey = null;
let syncInterval = null;

// =====================================================
// Encoding Utilities
// =====================================================
function toHex(uint8) {
  return Array.from(uint8)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

// =====================================================
// Key Derivation (PBKDF2)
// =====================================================
async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  
  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 250000,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  
  return key;
}

// =====================================================
// Password-based encryption/decryption (AES-GCM)
// =====================================================
async function encryptData(plaintext, password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  
  const key = await deriveKey(password, salt);
  
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv
    },
    key,
    enc.encode(plaintext)
  );
  
  // Format: salt:iv:ciphertext (all hex)
  return `${toHex(salt)}:${toHex(iv)}:${toHex(new Uint8Array(ciphertext))}`;
}

async function decryptData(ciphertext, password) {
  try {
    const enc = new TextEncoder();
    const dec = new TextDecoder();
    
    const parts = ciphertext.split(":");
    if (parts.length !== 3) {
      throw new Error("Invalid ciphertext format - expected salt:iv:ciphertext");
    }
    
    const salt = fromHex(parts[0]);
    const iv = fromHex(parts[1]);
    const data = fromHex(parts[2]);
    
    const key = await deriveKey(password, salt);
    
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv
      },
      key,
      data
    );
    
    return dec.decode(plaintext);
  } catch (error) {
    console.error("Decryption error:", error.message);
    
    if (error.message.includes("Invalid ciphertext format")) {
      throw new Error("Data corrupted: invalid encryption format");
    } else if (error.message.includes("The operation failed for an operation-specific reason")) {
      throw new Error("Decryption failed: Invalid password or corrupted data");
    } else {
      throw new Error("Decryption failed: " + error.message);
    }
  }
}

// =====================================================
// Mnemonic-based encryption/decryption (AES-GCM)
// =====================================================
async function encryptWithMnemonic(keyBytes, data) {
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );
  
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv
    },
    key,
    enc.encode(data)
  );
  
  // Format: iv:ciphertext (both hex)
  return `${toHex(iv)}:${toHex(new Uint8Array(ciphertext))}`;
}

async function decryptWithMnemonic(keyBytes, ciphertext) {
  try {
    const enc = new TextEncoder();
    const dec = new TextDecoder();
    
    const parts = ciphertext.split(":");
    if (parts.length !== 2) {
      throw new Error("Invalid mnemonic ciphertext format");
    }
    
    const iv = fromHex(parts[0]);
    const data = fromHex(parts[1]);
    
    const key = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );
    
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv
      },
      key,
      data
    );
    
    return dec.decode(plaintext);
  } catch (error) {
    console.error("Mnemonic decryption error:", error);
    throw new Error("Mnemonic decryption failed: " + error.message);
  }
}

// =====================================================
// Key Derivation Functions
// =====================================================
async function deriveIndexRoot(mnemonic) {
  const enc = new TextEncoder();

  const material = await crypto.subtle.importKey(
    "raw",
    enc.encode(mnemonic),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: enc.encode("arweave-vault-index-root"),
      iterations: 250000,
      hash: "SHA-256"
    },
    material,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign"]
  );
}

async function deriveMnemonicKey(mnemonic) {
  const enc = new TextEncoder();

  const material = await crypto.subtle.importKey(
    "raw",
    enc.encode(mnemonic),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: enc.encode("arweave-vault-mnemonic-layer"),
      iterations: 250000,
      hash: "SHA-256"
    },
    material,
    256
  );

  return new Uint8Array(bits);
}

async function deriveIndexKey(index) {
  if (!unlocked || !indexRootKey) {
    throw new Error("Vault locked");
  }

  const enc = new TextEncoder();
  const sig = await crypto.subtle.sign(
    "HMAC",
    indexRootKey,
    enc.encode(index.toString())
  );

  return toHex(new Uint8Array(sig));
}

// =====================================================
// Sync Management
// =====================================================
function startBackgroundSync() {
  if (syncInterval) {
    clearInterval(syncInterval);
  }
  
  if (unlocked) {
    syncInterval = setInterval(backgroundSync, 5 * 60 * 1000);
    console.log("Background sync started");
  }
}

function stopBackgroundSync() {
  if (syncInterval) {
    clearInterval(syncInterval);
    syncInterval = null;
    console.log("Background sync stopped");
  }
}

// =====================================================
// GraphQL Sync Function - UPDATED for version handling
// =====================================================
async function retrieveGraphQLSync() {
  if (!unlocked) throw new Error("Vault locked");

  // Get fresh storage data at the start
  const stored = await browser.storage.local.get({
    currentIndex: 0,
    entries: {},
    entryVersions: {} // New: track versions per entry
  });

  const results = [];
  let index = 0;
  let syncSuccessful = false;
  let entriesProcessed = 0;
  let entriesUpdated = 0;
  let newEntries = 0;

  console.log("Starting GraphQL sync...");

  try {
    while (true) {
      const indexKey = await deriveIndexKey(index);
      console.log(`Checking index ${index} with key: ${indexKey}`);

      // Get ALL transactions for this index key, not just latest
      const query = {
        query: `
          query {
            transactions(
              tags: [{ name: "${indexKey}", values: [] }]
              sort: HEIGHT_DESC
            ) {
              edges {
                node {
                  id
                  tags { name value }
                  block { height timestamp }
                }
              }
            }
          }
        `
      };

      const gqlRes = await fetch("https://arweave.net/graphql", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(query)
      });

      if (!gqlRes.ok) {
        console.error("GraphQL request failed:", await gqlRes.text());
        break;
      }

      const gqlJson = await gqlRes.json();
      const edges = gqlJson?.data?.transactions?.edges;
      
      if (!edges || edges.length === 0) {
        console.log(`No transactions found for index ${index}, stopping sync`);
        break;
      }

      console.log(`Found ${edges.length} versions for index ${index}`);
      
      // Process each version, newest first
      let latestVersion = null;
      const versions = [];
      
      for (const edge of edges) {
        const node = edge.node;
        const tag = node.tags.find(t => t.name === indexKey);
        
        if (!tag) {
          console.log(`No tag found for index ${index} version ${node.id}, skipping`);
          continue;
        }

        entriesProcessed++;
        console.log(`Processing version ${node.id} for index ${index}`);
        
        try {
          // 1. Decrypt txid
          let fileTxId;
          try {
            fileTxId = await decryptData(tag.value, sessionPassword);
            console.log(`Decrypted fileTxId: ${fileTxId ? 'Success' : 'Failed'}`);
          } catch (decryptError) {
            console.log(`Could not decrypt txid for ${node.id}:`, decryptError.message);
            continue;
          }

          // 2. Fetch remote ciphertext
          const resp = await fetch(`https://arweave.net/${fileTxId}`);
          if (!resp.ok) {
            console.log(`Failed to fetch transaction ${fileTxId}: ${resp.status}, skipping`);
            continue;
          }
          
          const remoteCiphertext = await resp.text();
          console.log(`Fetched remote ciphertext (${remoteCiphertext.length} chars)`);

          // 3. Remove mnemonic layer
          let passwordCiphertext;
          try {
            passwordCiphertext = await decryptWithMnemonic(mnemonicKey, remoteCiphertext);
            console.log(`Mnemonic decryption successful (${passwordCiphertext.length} chars)`);
          } catch (mnemonicError) {
            console.log(`Mnemonic decryption failed for ${node.id}:`, mnemonicError.message);
            continue;
          }

          // 4. Decrypt for processing
          let plaintext;
          try {
            plaintext = await decryptData(passwordCiphertext, sessionPassword);
            console.log(`Password decryption successful (${plaintext.length} chars)`);
          } catch (finalDecryptError) {
            console.log(`Final decryption failed for ${node.id}:`, finalDecryptError.message);
            continue;
          }

          let entryData;
          try {
            entryData = JSON.parse(plaintext);
            console.log(`JSON parsed successfully for entry: ${entryData.id || 'no-id'}`);
          } catch (parseError) {
            console.log(`JSON parse failed for ${node.id}:`, parseError.message);
            continue;
          }
          
          const versionData = {
            txId: node.id,
            fileTxId,
            timestamp: node.block?.timestamp * 1000 || Date.now(),
            blockHeight: node.block?.height || 0,
            data: entryData,
            passwordCiphertext
          };
          
          versions.push(versionData);
          
          // Track the latest non-deleted version
          if (!latestVersion && !entryData.deleted) {
            latestVersion = versionData;
          }
          
        } catch (e) {
          console.error(`❌ Error processing version ${node.id}:`, e);
        }
      }
      
      // Store versions for this index
      if (versions.length > 0) {
        // Store all versions in entryVersions
        if (!stored.entryVersions[index]) {
          stored.entryVersions[index] = [];
        }
        
        // Merge versions, keeping only unique txIds
        const existingTxIds = new Set(stored.entryVersions[index].map(v => v.txId));
        const newVersions = versions.filter(v => !existingTxIds.has(v.txId));
        
        if (newVersions.length > 0) {
          stored.entryVersions[index] = [...stored.entryVersions[index], ...newVersions];
          
          // Sort by block height (newest first)
          stored.entryVersions[index].sort((a, b) => b.blockHeight - a.blockHeight);
          
          console.log(`Added ${newVersions.length} new versions for index ${index}`);
        }
      }
      
      // Update main entry if we have a latest version
      if (latestVersion) {
        const entryData = latestVersion.data;
        const entryId = entryData.id || `entry_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        
        console.log(`Processing entry: ${entryId}`);
        
        // Check if we already have this entry by ID
        let existingIndex = -1;
        if (entryId) {
          for (let i = 0; i < stored.currentIndex; i++) {
            const existing = stored.entries[i];
            if (existing && existing.entryId === entryId) {
              existingIndex = i;
              console.log(`Found existing entry at index ${i}`);
              break;
            }
          }
        }
        
        const storageIndex = existingIndex >= 0 ? existingIndex : stored.currentIndex;
        
        // Update local storage
        stored.entries[storageIndex] = {
          fileTxId: latestVersion.fileTxId,
          passwordCiphertext: latestVersion.passwordCiphertext,
          entryId: entryId,
          timestamp: latestVersion.timestamp,
          latestTxId: latestVersion.txId,
          storageIndex: storageIndex
        };
        
        if (existingIndex === -1) {
          stored.currentIndex++;
          newEntries++;
        } else {
          entriesUpdated++;
        }
        
        // Add the storage index to the entry data
        entryData._storageIndex = storageIndex;
        
        results.push({ 
          index: storageIndex, 
          data: JSON.stringify(entryData),
          timestamp: latestVersion.timestamp,
          isUpdate: existingIndex !== -1,
          entryId: entryId
        });
        
        syncSuccessful = true;
        console.log(`✅ Successfully synced entry at index ${index}`);
      } else if (versions.length > 0) {
        console.log(`⚠️ All versions for index ${index} are deleted entries`);
      }
      
      index++;
    }
  } catch (outerError) {
    console.error("❌ Outer sync error:", outerError);
  }

  // Only update storage if we successfully synced something
  if (syncSuccessful) {
    // Get current storage to merge
    const currentStorage = await browser.storage.local.get({
      currentIndex: 0,
      entries: {},
      entryVersions: {}
    });
    
    // Merge entries
    const mergedEntries = { ...currentStorage.entries, ...stored.entries };
    const mergedCurrentIndex = Math.max(currentStorage.currentIndex, stored.currentIndex);
    
    // Merge versions
    const mergedVersions = { ...currentStorage.entryVersions };
    for (const [index, versions] of Object.entries(stored.entryVersions)) {
      if (!mergedVersions[index]) {
        mergedVersions[index] = versions;
      } else {
        // Merge unique versions
        const existingTxIds = new Set(mergedVersions[index].map(v => v.txId));
        const newVersions = versions.filter(v => !existingTxIds.has(v.txId));
        if (newVersions.length > 0) {
          mergedVersions[index] = [...mergedVersions[index], ...newVersions];
          mergedVersions[index].sort((a, b) => b.blockHeight - a.blockHeight);
        }
      }
    }
    
    await browser.storage.local.set({
      entries: mergedEntries,
      currentIndex: mergedCurrentIndex,
      entryVersions: mergedVersions
    });
    
    const totalProcessed = entriesUpdated + newEntries;
    console.log(`✅ Sync completed: ${totalProcessed} entries updated (${newEntries} new, ${entriesUpdated} updated). ${entriesProcessed} versions processed.`);
  } else {
    console.log(`ℹ️ No entries were successfully synced (checked ${entriesProcessed} versions)`);
  }

  return { 
    ok: true, 
    mode: "graphql", 
    results,
    syncSuccessful: syncSuccessful,
    entriesProcessed: entriesProcessed,
    entriesUpdated: entriesUpdated,
    newEntries: newEntries,
    message: syncSuccessful ? `Synced ${results.length} entries from Arweave` : "No new entries found on Arweave"
  };
}

// =====================================================
// Background Sync (Quiet mode - doesn't notify popup)
// =====================================================
async function backgroundSync() {
  try {
    // Only sync if vault is unlocked and we have a session password
    if (unlocked && sessionPassword) {
      console.log("🔄 Running background sync...");
      
      // Run the sync quietly
      const result = await retrieveGraphQLSync();
      
      if (result.ok && result.syncSuccessful) {
        console.log(`✅ Background sync completed: ${result.results.length} entries processed`);
      } else {
        console.log("ℹ️ Background sync: No new entries found");
      }
    }
  } catch (error) {
    console.error("❌ Background sync failed:", error.message);
  }
}

// =====================================================
// Message Handler
// =====================================================
browser.runtime.onMessage.addListener(async (msg) => {
  const { action } = msg;

  // ===================================================
  // INIT / LOGIN / UNLOCK
  // ===================================================
  if (action === "init-vault" || action === "unlock") {
    const { mnemonic, password } = msg;
    if (!password) throw new Error("Password required");

    let mnemonicPlain = mnemonic;

    // Password-only unlock
    if (!mnemonicPlain) {
      const stored = await browser.storage.local.get("encryptedMnemonic");
      if (!stored.encryptedMnemonic) {
        throw new Error("Vault not initialized");
      }
      mnemonicPlain = await decryptData(stored.encryptedMnemonic, password);
    }
    // Init / login with mnemonic
    else {
      const encryptedMnemonic = await encryptData(mnemonicPlain, password);
      await browser.storage.local.set({
        vaultInitialized: true,
        encryptedMnemonic
      });
    }

    indexRootKey = await deriveIndexRoot(mnemonicPlain);
    mnemonicKey = await deriveMnemonicKey(mnemonicPlain);
    sessionPassword = password;
    unlocked = true;

    // Don't clear storage on unlock - preserve existing entries
    // Only clear if storage is corrupted
    try {
      const stored = await browser.storage.local.get({
        currentIndex: 0,
        entries: {},
        entryVersions: {}
      });
      
      // Validate storage
      let validEntries = {};
      let maxIndex = 0;
      
      for (let i = 0; i < stored.currentIndex; i++) {
        const entry = stored.entries[i];
        if (entry && entry.passwordCiphertext && entry.entryId) {
          validEntries[i] = entry;
          maxIndex = i + 1;
        }
      }
      
      // Update with cleaned entries
      await browser.storage.local.set({
        entries: validEntries,
        currentIndex: maxIndex,
        entryVersions: stored.entryVersions || {}
      });
      
      console.log(`Validated storage: ${maxIndex} valid entries found, ${Object.keys(stored.entryVersions || {}).length} version sets`);
    } catch (e) {
      console.error("Storage validation failed:", e);
      // Clear corrupted storage
      await browser.storage.local.remove("currentIndex");
      await browser.storage.local.remove("entries");
      await browser.storage.local.remove("entryVersions");
    }

    // Start background sync after a delay
    setTimeout(() => {
      startBackgroundSync();
      // Run immediate sync
      backgroundSync();
    }, 1000);

    console.log("✅ Vault unlocked successfully");

    return { ok: true };
  }

  // ===================================================
  // LOCK
  // ===================================================
  if (action === "lock") {
    unlocked = false;
    sessionPassword = null;
    mnemonicKey = null;
    indexRootKey = null;
    
    // Stop background sync
    stopBackgroundSync();
    
    // DO NOT clear storage on lock - keep entries for next unlock
    // Only clear volatile session state
    
    console.log("🔒 Vault locked (storage preserved)");
    
    return { ok: true };
  }

  // ===================================================
  // UI UPDATED NOTIFICATION
  // ===================================================
  if (action === "ui-updated") {
    // Force a refresh of local storage structure
    const stored = await browser.storage.local.get({
      currentIndex: 0,
      entries: {},
      entryVersions: {}
    });
    
    // Re-index entries to ensure consistency
    const validEntries = {};
    let maxIndex = 0;
    
    for (let i = 0; i < stored.currentIndex; i++) {
      const entry = stored.entries[i];
      if (entry && entry.passwordCiphertext && entry.entryId) {
        validEntries[i] = entry;
        maxIndex = i + 1;
      }
    }
    
    await browser.storage.local.set({
      entries: validEntries,
      currentIndex: maxIndex,
      entryVersions: stored.entryVersions || {}
    });
    
    console.log(`🔄 UI updated notification processed. ${maxIndex} valid entries.`);
    
    return { ok: true };
  }

  // ===================================================
  // STORE ENTRY
  // ===================================================
  if (action === "store") {
    if (!unlocked) throw new Error("Vault locked");

    const { data, entryId, isNewEntry } = msg;
    
    const stored = await browser.storage.local.get({
      currentIndex: 0,
      entries: {},
      entryVersions: {}
    });

    let index;
    let shouldUseNewIndex = true;
    
    // Parse the data to get entry info
    const entryData = JSON.parse(data);
    const actualEntryId = entryId || entryData.id;
    
    console.log(`Storing entry: ${actualEntryId}, isNew: ${isNewEntry}`);
    
    // If not a new entry, try to find existing index
    if (!isNewEntry && actualEntryId) {
      // Search through existing entries to find this entryId
      for (let i = 0; i < stored.currentIndex; i++) {
        const existingEntry = stored.entries[i];
        if (existingEntry && existingEntry.entryId === actualEntryId) {
          index = i;
          shouldUseNewIndex = false;
          console.log(`Found existing entry at index ${i}`);
          break;
        }
      }
    }
    
    // If we didn't find an existing index, use a new one
    if (shouldUseNewIndex) {
      index = stored.currentIndex;
      stored.currentIndex += 1;
      console.log(`Using new index: ${index}`);
    }

    const indexKey = await deriveIndexKey(index);
    console.log(`Derived index key: ${indexKey.substring(0, 16)}...`);

    // 1. Encrypt data (password layer)
    const passwordCiphertext = await encryptData(data, sessionPassword);
    console.log(`Password encryption successful (${passwordCiphertext.length} chars)`);

    // 2. Encrypt for remote (mnemonic layer)
    const remoteCiphertext = await encryptWithMnemonic(mnemonicKey, passwordCiphertext);
    console.log(`Mnemonic encryption successful (${remoteCiphertext.length} chars)`);

    let fileTxId = null;
    let mapTxId = null;
    
    try {
      // 3. Try to upload FILE tx (only if agent is running)
      console.log(`Attempting to upload to Arweave agent at ${AGENT_BASE}`);
      const fileRes = await fetch(`${AGENT_BASE}/store/file`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          encryptedFile: remoteCiphertext
        })
      });

      if (fileRes.ok) {
        const fileData = await fileRes.json();
        fileTxId = fileData.fileTxId;
        console.log(`File uploaded successfully: ${fileTxId}`);

        // 4. Encrypt txid (password only)
        const encryptedTxId = await encryptData(fileTxId, sessionPassword);

        // 5. Upload MAP tx
        const mapRes = await fetch(`${AGENT_BASE}/store/map`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            indexKey,
            encryptedTxId
          })
        });

        if (mapRes.ok) {
          const mapData = await mapRes.json();
          mapTxId = mapData.mapTxId;
          console.log(`Map uploaded successfully: ${mapTxId}`);
        } else {
          console.log("Map upload failed:", await mapRes.text());
        }
      } else {
        console.log("File upload failed:", await fileRes.text());
      }
    } catch (e) {
      console.log("Arweave agent not available, storing locally only:", e.message);
    }

    // 6. Cache locally (even if upload failed)
    stored.entries[index] = {
      fileTxId,
      mapTxId,
      passwordCiphertext,
      entryId: actualEntryId,
      timestamp: Date.now(),
      storageIndex: index
    };

    await browser.storage.local.set({
      currentIndex: stored.currentIndex,
      entries: stored.entries,
      entryVersions: stored.entryVersions
    });

    console.log(`✅ Entry stored locally at index ${index}. Total entries: ${stored.currentIndex}`);

    // Notify popup that storage was updated
    try {
      await browser.runtime.sendMessage({ 
        action: "storage-updated",
        type: isNewEntry ? "created" : "updated",
        entryId: actualEntryId
      });
    } catch (e) {
      // Popup might be closed
    }

    return { ok: true, index, entryId: actualEntryId };
  }

  // ===================================================
  // RETRIEVE LOCAL ENTRIES - FIXED VERSION
  // ===================================================
  if (action === "retrieve-local") {
    if (!unlocked) throw new Error("Vault locked");

    // Always get fresh storage data
    const stored = await browser.storage.local.get({
      currentIndex: 0,
      entries: {},
      entryVersions: {}
    });

    const results = [];

    console.log(`Retrieving local entries, currentIndex: ${stored.currentIndex}, entries keys:`, Object.keys(stored.entries || {}));

    // Check all indices up to currentIndex
    for (let i = 0; i < stored.currentIndex; i++) {
      const entry = stored.entries[i];
      
      if (!entry || !entry.passwordCiphertext) {
        console.log(`Skipping index ${i} - no valid entry`);
        continue;
      }

      try {
        console.log(`Decrypting entry at index ${i}, entryId: ${entry.entryId || 'no-id'}`);
        const plaintext = await decryptData(entry.passwordCiphertext, sessionPassword);
        const entryData = JSON.parse(plaintext);
        
        // Ensure entry has an ID (use stored entryId if missing)
        if (!entryData.id && entry.entryId) {
          entryData.id = entry.entryId;
        }
        
        // Add the storage index to the entry data
        entryData._storageIndex = i;
        
        results.push({ 
          index: i, 
          data: JSON.stringify(entryData),
          timestamp: entry.timestamp || Date.now(),
          entryId: entryData.id
        });
        
        console.log(`✅ Retrieved entry at index ${i}: ${entryData.id || 'no-id'}`);
      } catch (e) {
        console.error(`❌ Failed to decrypt entry at index ${i}:`, e.message);
        // Don't delete immediately, just skip
        console.log(`Keeping encrypted entry at index ${i} for future attempts`);
      }
    }

    // Sort by timestamp (newest first)
    results.sort((a, b) => b.timestamp - a.timestamp);

    console.log(`✅ Retrieved ${results.length} local entries from storage`);
    
    return { 
      ok: true, 
      mode: "local", 
      results,
      entryVersions: stored.entryVersions || {}
    };
  }

  // ===================================================
  // RETRIEVE VERSION HISTORY
  // ===================================================
  if (action === "get-version-history") {
    if (!unlocked) throw new Error("Vault locked");
    
    const { entryId } = msg;
    
    // Find which index this entry is at
    const stored = await browser.storage.local.get({
      currentIndex: 0,
      entries: {},
      entryVersions: {}
    });
    
    let targetIndex = -1;
    for (let i = 0; i < stored.currentIndex; i++) {
      const entry = stored.entries[i];
      if (entry && entry.entryId === entryId) {
        targetIndex = i;
        break;
      }
    }
    
    if (targetIndex === -1) {
      return { ok: false, error: "Entry not found" };
    }
    
    const versions = stored.entryVersions[targetIndex] || [];
    
    // Process versions to include decrypted data
    const processedVersions = [];
    for (const version of versions) {
      try {
        const plaintext = await decryptData(version.passwordCiphertext, sessionPassword);
        const entryData = JSON.parse(plaintext);
        processedVersions.push({
          ...version,
          data: entryData
        });
      } catch (e) {
        console.error(`Failed to decrypt version ${version.txId}:`, e);
      }
    }
    
    return {
      ok: true,
      versions: processedVersions,
      currentIndex: targetIndex
    };
  }

  // ===================================================
  // RETRIEVE FROM GRAPHQL (SYNC) - FOR POPUP
  // ===================================================
  if (action === "retrieve-graphql") {
    if (!unlocked) throw new Error("Vault locked");

    try {
      console.log("🔄 Manual sync requested from popup");
      const result = await retrieveGraphQLSync();
      
      // Only notify popup if it's open
      try {
        await browser.runtime.sendMessage({ 
          action: "storage-updated",
          type: "synced",
          count: result.results.length,
          syncSuccessful: result.syncSuccessful,
          entriesProcessed: result.entriesProcessed,
          timestamp: Date.now()
        });
      } catch (e) {
        // Popup is closed, that's fine
      }

      return result;
    } catch (syncError) {
      console.error("❌ GraphQL sync failed:", syncError);
      return { 
        ok: false, 
        error: syncError.message,
        message: "Sync failed: " + syncError.message
      };
    }
  }

  // ===================================================
  // CLEANUP (Optional cleanup function)
  // ===================================================
  if (action === "cleanup") {
    if (!unlocked) throw new Error("Vault locked");
    
    const stored = await browser.storage.local.get({
      currentIndex: 0,
      entries: {},
      entryVersions: {}
    });
    
    let removedCount = 0;
    const newEntries = {};
    const newVersions = {};
    let newIndex = 0;
    
    // Reindex and remove corrupted entries
    for (let i = 0; i < stored.currentIndex; i++) {
      const entry = stored.entries[i];
      if (entry && entry.passwordCiphertext) {
        try {
          // Try to decrypt to verify entry is valid
          const plaintext = await decryptData(entry.passwordCiphertext, sessionPassword);
          JSON.parse(plaintext); // Verify JSON is valid
          newEntries[newIndex] = {
            ...entry,
            storageIndex: newIndex
          };
          
          // Keep versions for this index if they exist
          if (stored.entryVersions[i]) {
            newVersions[newIndex] = stored.entryVersions[i];
          }
          
          newIndex++;
        } catch (e) {
          console.log(`Removing corrupted entry at index ${i}`);
          removedCount++;
        }
      }
    }
    
    await browser.storage.local.set({
      entries: newEntries,
      currentIndex: newIndex,
      entryVersions: newVersions
    });
    
    console.log(`🔄 Cleanup completed: removed ${removedCount} entries, ${newIndex} remaining`);
    
    return { 
      ok: true, 
      removed: removedCount,
      remaining: newIndex 
    };
  }

  // ===================================================
  // GET VAULT INFO (For debugging)
  // ===================================================
  if (action === "get-vault-info") {
    const stored = await browser.storage.local.get({
      vaultInitialized: false,
      currentIndex: 0,
      encryptedMnemonic: null,
      entries: {},
      entryVersions: {}
    });
    
    const entries = stored.entries || {};
    const entryCount = Object.keys(entries).filter(k => entries[k]).length;
    const versionCount = Object.keys(stored.entryVersions || {}).length;
    
    return {
      ok: true,
      vaultInitialized: stored.vaultInitialized,
      unlocked: unlocked,
      entryCount: entryCount,
      currentIndex: stored.currentIndex,
      hasEncryptedMnemonic: !!stored.encryptedMnemonic,
      hasSessionPassword: !!sessionPassword,
      hasMnemonicKey: !!mnemonicKey,
      hasIndexRootKey: !!indexRootKey,
      storageDetails: {
        entriesCount: entryCount,
        entriesIndices: Object.keys(entries),
        versionSets: versionCount,
        totalVersions: Object.values(stored.entryVersions || {}).reduce((sum, arr) => sum + arr.length, 0)
      }
    };
  }

  // Unknown action
  console.warn("Unknown action received:", action);
  return { ok: false, error: "Unknown action: " + action };
});

// =====================================================
// Startup Cleanup
// =====================================================
async function startupCleanup() {
  try {
    // Clear any invalid session state on startup
    const { vaultInitialized } = await browser.storage.local.get("vaultInitialized");
    
    if (!vaultInitialized) {
      // Reset everything if vault is not initialized
      await browser.storage.local.remove("entries");
      await browser.storage.local.remove("currentIndex");
      await browser.storage.local.remove("entryVersions");
      console.log("🔄 Startup cleanup: Reset storage (vault not initialized)");
    } else {
      console.log("🔄 Startup cleanup: Vault is initialized, preserving storage");
      
      // Validate storage structure
      const stored = await browser.storage.local.get({
        currentIndex: 0,
        entries: {},
        entryVersions: {}
      });
      
      console.log(`Current storage: index=${stored.currentIndex}, entries=${Object.keys(stored.entries || {}).length}, versions=${Object.keys(stored.entryVersions || {}).length}`);
    }
  } catch (error) {
    console.error("❌ Startup cleanup failed:", error);
  }
}

// Run cleanup on extension startup
startupCleanup();

// =====================================================
// Install/Update Handler
// =====================================================
browser.runtime.onInstalled.addListener((details) => {
  if (details.reason === "install") {
    console.log("🎉 Extension installed");
  } else if (details.reason === "update") {
    console.log("🔄 Extension updated from version", details.previousVersion);
  }
});
