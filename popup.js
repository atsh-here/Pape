// Wait for DOM to be fully ready
function waitForElement(selector, timeout = 5000) {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    
    function check() {
      const element = document.querySelector(selector);
      if (element) {
        resolve(element);
      } else if (Date.now() - startTime > timeout) {
        reject(new Error(`Element ${selector} not found after ${timeout}ms`));
      } else {
        setTimeout(check, 100);
      }
    }
    
    check();
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  initializeApp();
});

async function initializeApp() {
  const output = document.getElementById("output");
  let currentEntryId = null;
  let entries = {};
  let isEditing = false;
  let generatedMnemonic = "";
  let showingVersionHistory = false;
  let currentVersions = [];
  
  // TOTP Variables
  let totpInterval = null;
  let currentTotpSecret = '';

  // =====================================================
  // Helper Functions
  // =====================================================

  // Show screens
  function show(id) {
    console.log(`Showing screen: ${id}`);
    document.querySelectorAll(".screen").forEach(s =>
      s.classList.remove("active")
    );
    const screen = document.getElementById(id);
    if (screen) {
      screen.classList.add("active");
    }
    
    // If showing vault, load entries after DOM is ready
    if (id === "screen-vault") {
      // Clear current selection
      currentEntryId = null;
      entries = {};
      
      // Wait for DOM to be ready
      setTimeout(() => {
        // Double-check we're still on the vault screen
        const vaultScreen = document.getElementById("screen-vault");
        if (vaultScreen && vaultScreen.classList.contains("active")) {
          loadEntries();
          // Initialize copy buttons when vault loads
          setupCopyButtons();
          setupTOTPToggle();
        }
      }, 100);
    }
  }

  // Generate entry ID
  function generateEntryId() {
    return 'entry_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  }

  // Password validation
  function validatePassword(password) {
    const reasons = [];
    if (password.length < 8) reasons.push("at least 8 characters");
    
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSymbol = /[^A-Za-z0-9]/.test(password);
    const classesMet = [hasLower, hasUpper, hasNumber, hasSymbol].filter(Boolean).length;
    if (classesMet < 3) reasons.push("at least 3 of: lowercase, uppercase, number, symbol");
    
    return reasons;
  }

  // BIP-39 mnemonic checksum validation
  async function validateMnemonicChecksum(mnemonic) {
    const words = mnemonic.trim().split(/\s+/);
    if (words.length !== 12) return "Mnemonic must be exactly 12 words";
    
    const indices = [];
    for (const word of words) {
      const idx = BIP39_WORDLIST.indexOf(word);
      if (idx === -1) return `Invalid word: "${word}"`;
      indices.push(idx);
    }
    
    const bits = indices.map(i => i.toString(2).padStart(11, "0")).join("");
    const entropyBits = bits.slice(0, 128);
    const checksumBits = bits.slice(128);
    
    const entropy = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      entropy[i] = parseInt(entropyBits.slice(i * 8, (i + 1) * 8), 2);
    }
    
    const hashBuffer = await crypto.subtle.digest("SHA-256", entropy);
    const hash = new Uint8Array(hashBuffer);
    const expectedChecksum = hash[0].toString(2).padStart(8, "0").slice(0, 4);
    
    if (checksumBits !== expectedChecksum) {
      return "Mnemonic checksum is invalid (possible typo)";
    }
    
    return null;
  }

  // Generate BIP-39 mnemonic
  async function generateBip39Mnemonic() {
    const entropy = new Uint8Array(16);
    crypto.getRandomValues(entropy);
    
    const hashBuffer = await crypto.subtle.digest("SHA-256", entropy);
    const hash = new Uint8Array(hashBuffer);
    
    const entropyBits = [...entropy].map(b => b.toString(2).padStart(8, "0")).join("");
    const checksumBits = hash[0].toString(2).padStart(8, "0").slice(0, 4);
    const bits = entropyBits + checksumBits;
    
    const words = [];
    for (let i = 0; i < bits.length; i += 11) {
      const idx = parseInt(bits.slice(i, i + 11), 2);
      words.push(BIP39_WORDLIST[idx]);
    }
    
    return words.join(" ");
  }

  // Format time
  function formatTime(timestamp) {
    if (!timestamp) return '';
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;
    
    if (diff < 60 * 60 * 1000) {
      return 'Just now';
    } else if (diff < 24 * 60 * 60 * 1000) {
      return 'Today';
    } else if (diff < 7 * 24 * 60 * 60 * 1000) {
      return `${Math.floor(diff / (24 * 60 * 60 * 1000))}d ago`;
    } else {
      return date.toLocaleDateString();
    }
  }

  // Format detailed time
  function formatDetailedTime(timestamp) {
    if (!timestamp) return '';
    const date = new Date(timestamp);
    return date.toLocaleString();
  }

  // Show output message
  function showOutput(message, isError = false) {
    if (!output) {
      console.log("Output element not found, message:", message);
      return;
    }
    
    output.textContent = message;
    output.style.display = 'block';
    output.style.color = isError ? '#f87171' : '#4ade80';
    
    setTimeout(() => {
      if (output) {
        output.style.display = 'none';
      }
    }, 3000);
  }

  // Get category color
  function getCategoryColor(category) {
    const colors = {
      'social': '#667eea',
      'finance': '#48bb78',
      'work': '#ed8936',
      'personal': '#9f7aea',
      'other': '#a0aec0'
    };
    return colors[category] || '#a0aec0';
  }

  // Generate random password
  function generatePassword(length = 16) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    let password = '';
    for (let i = 0; i < length; i++) {
      password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return password;
  }

  // Create entry element
  function createEntryElement(container, id, entry, isDeleted) {
    const entryElement = document.createElement('div');
    entryElement.className = `entry-item ${isDeleted ? 'deleted' : ''} ${currentEntryId == id ? 'active' : ''}`;
    entryElement.dataset.id = id;
    
    const firstLetter = entry.title ? entry.title.charAt(0).toUpperCase() : '?';
    const displayName = entry.title || entry.website || 'Unnamed Entry';
    const displayUsername = entry.username || 'No username';
    
    entryElement.innerHTML = `
      <div class="entry-item-header">
        <div class="entry-item-icon" style="background: ${getCategoryColor(entry.category)}; opacity: ${isDeleted ? 0.5 : 1}">
          ${firstLetter}
        </div>
        <div>
          <div class="entry-item-title">${displayName}</div>
          <div class="entry-item-username">${displayUsername}</div>
        </div>
      </div>
      <div class="entry-item-actions">
        ${isDeleted ? '<i class="fas fa-trash" style="color: var(--danger); margin-right: 5px;"></i>' : ''}
        <div class="entry-item-time">
          ${formatTime(entry.modified)}
        </div>
      </div>
    `;
    
    entryElement.addEventListener('click', () => {
      if (showingVersionHistory) return;
      document.querySelectorAll('.entry-item').forEach(el => el.classList.remove('active'));
      entryElement.classList.add('active');
      showEntryDetail(id);
    });
    
    container.appendChild(entryElement);
  }

  // =====================================================
  // COPY FUNCTIONALITY (NEW)
  // =====================================================

  // Setup copy buttons for all fields
  function setupCopyButtons() {
    console.log("Setting up copy buttons...");
    
    // Setup copy buttons for all fields
    document.querySelectorAll('.copy-btn[data-field]').forEach(btn => {
      // Remove existing listeners to avoid duplicates
      const newBtn = btn.cloneNode(true);
      btn.parentNode.replaceChild(newBtn, btn);
      
      newBtn.addEventListener('click', async function() {
        const fieldType = this.dataset.field;
        let textToCopy = '';
        
        switch(fieldType) {
          case 'website':
            textToCopy = document.getElementById('entry-website').value;
            break;
          case 'username':
            textToCopy = document.getElementById('entry-username').value;
            break;
          case 'password':
            textToCopy = document.getElementById('entry-password').value;
            break;
          case 'totp':
            textToCopy = document.getElementById('entry-totp').value;
            break;
          case 'notes':
            textToCopy = document.getElementById('entry-notes').value;
            break;
        }
        
        if (textToCopy && textToCopy.trim()) {
          await copyToClipboard(textToCopy, this, fieldType);
        } else {
          showOutput(`No ${fieldType} to copy`, true);
        }
      });
    });
    
    // TOTP code copy button
    const copyTOTPCodeBtn = document.getElementById('copy-totp-code');
    if (copyTOTPCodeBtn) {
      const newBtn = copyTOTPCodeBtn.cloneNode(true);
      copyTOTPCodeBtn.parentNode.replaceChild(newBtn, copyTOTPCodeBtn);
      
      newBtn.addEventListener('click', async function() {
        const totpCode = document.getElementById('totp-code').textContent;
        if (totpCode && totpCode !== '------' && totpCode !== 'ERROR') {
          await copyToClipboard(totpCode, this, 'TOTP code');
        } else {
          showOutput('No TOTP code available', true);
        }
      });
    }
    
    // QR modal copy secret button
    const copyQrSecretBtn = document.getElementById('copy-qr-secret');
    if (copyQrSecretBtn) {
      const newBtn = copyQrSecretBtn.cloneNode(true);
      copyQrSecretBtn.parentNode.replaceChild(newBtn, copyQrSecretBtn);
      
      newBtn.addEventListener('click', async function() {
        const secretText = document.getElementById('qr-secret-text').textContent;
        if (secretText && secretText !== '••••••••••••••••') {
          // Remove spaces for the actual secret
          const cleanSecret = secretText.replace(/\s/g, '');
          await copyToClipboard(cleanSecret, this, 'TOTP secret');
        } else {
          showOutput('Secret not revealed', true);
        }
      });
    }
    
    console.log("Copy buttons setup complete");
  }

  // Generic copy to clipboard function
  async function copyToClipboard(text, button, fieldName = '') {
    try {
      await navigator.clipboard.writeText(text);
      
      // Visual feedback
      if (button) {
        const originalHTML = button.innerHTML;
        const originalClass = button.className;
        
        button.innerHTML = '<i class="fas fa-check"></i>';
        button.className = originalClass + ' copied';
        
        setTimeout(() => {
          button.innerHTML = originalHTML;
          button.className = originalClass;
        }, 1000);
      }
      
      // Show success message
      const fieldDisplayName = fieldName ? `${fieldName} ` : '';
      showOutput(`${fieldDisplayName}copied to clipboard!`);
      
    } catch (err) {
      console.error('Failed to copy:', err);
      showOutput('Failed to copy to clipboard', true);
    }
  }

  // TOTP secret toggle visibility
  function setupTOTPToggle() {
    const toggleTOTPBtn = document.getElementById('toggle-totp');
    const totpField = document.getElementById('entry-totp');
    
    if (toggleTOTPBtn && totpField) {
      // Remove existing listener to avoid duplicates
      const newBtn = toggleTOTPBtn.cloneNode(true);
      toggleTOTPBtn.parentNode.replaceChild(newBtn, toggleTOTPBtn);
      
      newBtn.onclick = function() {
        const icon = this.querySelector("i");
        
        if (totpField.type === "password") {
          totpField.type = "text";
          if (icon) icon.className = "fas fa-eye-slash";
        } else {
          totpField.type = "password";
          if (icon) icon.className = "fas fa-eye";
        }
      };
    }
  }

  // =====================================================
  // TOTP Functions
  // =====================================================

  // Start TOTP timer and code generation
  function startTOTPDisplay(secret) {
    if (!secret || !secret.trim()) return;
    
    currentTotpSecret = secret;
    const totpDisplay = document.getElementById('totp-display');
    const totpCode = document.getElementById('totp-code');
    const totpTimer = document.getElementById('totp-timer');
    const progressBar = document.getElementById('totp-progress-bar');
    
    if (!totpDisplay || !totpCode || !totpTimer || !progressBar) return;
    
    // Show TOTP display
    totpDisplay.style.display = 'block';
    
    // Update function
    const updateTOTP = async () => {
      try {
        // Generate current code
        const code = await TOTP.generate(secret);
        totpCode.textContent = code;
        
        // Update timer
        const timeRemaining = TOTP.getTimeRemaining();
        totpTimer.textContent = `${timeRemaining}s`;
        
        // Update progress bar
        const progress = (timeRemaining / 30) * 100;
        progressBar.style.width = `${progress}%`;
        progressBar.style.transition = 'width 1s linear';
        
        // Update colors based on time
        if (timeRemaining < 10) {
          totpTimer.style.background = 'var(--danger)';
          progressBar.style.background = 'var(--danger)';
        } else if (timeRemaining < 20) {
          totpTimer.style.background = 'var(--warning)';
          progressBar.style.background = 'var(--warning)';
        } else {
          totpTimer.style.background = 'var(--accent)';
          progressBar.style.background = 'var(--accent)';
        }
      } catch (error) {
        console.error('Error generating TOTP:', error);
        totpCode.textContent = 'ERROR';
        totpTimer.textContent = '0s';
        progressBar.style.width = '0%';
      }
    };
    
    // Initial update
    updateTOTP();
    
    // Update every second
    if (totpInterval) clearInterval(totpInterval);
    totpInterval = setInterval(updateTOTP, 1000);
  }

  // Stop TOTP display
  function stopTOTPDisplay() {
    if (totpInterval) {
      clearInterval(totpInterval);
      totpInterval = null;
    }
    
    const totpDisplay = document.getElementById('totp-display');
    if (totpDisplay) {
      totpDisplay.style.display = 'none';
    }
  }

  // Generate QR Code from secret
  function generateQRCodeFromSecret(secret, accountName, issuer) {
    if (!secret || !secret.trim()) return;
    
    // Clean the secret (remove spaces, convert to uppercase)
    const cleanSecret = secret.replace(/\s/g, '').toUpperCase();
    
    // Validate it's a valid base32 secret
    const base32Regex = /^[A-Z2-7]+=*$/;
    if (!base32Regex.test(cleanSecret)) {
      showOutput("Invalid TOTP secret format. Must be base32 (A-Z2-7)", true);
      return;
    }
    
    const url = TOTP.generateQRCodeURL(cleanSecret, accountName, issuer);
    const canvas = document.getElementById('qr-canvas');
    const modal = document.getElementById('qr-modal');
    const qrSecretText = document.getElementById('qr-secret-text');
    const qrSecretDisplay = document.getElementById('qr-secret-display');
    const revealSecretBtn = document.getElementById('reveal-secret-btn');
    
    if (!canvas || !modal || !qrSecretText || !qrSecretDisplay || !revealSecretBtn) return;
    
    // Simple QR code generation 
    const ctx = canvas.getContext('2d');
    
    // Clear canvas
    ctx.fillStyle = 'white';
    ctx.fillRect(0, 0, 200, 200);
    
    // Draw QR placeholder (in production, use a proper QR library)
    ctx.fillStyle = 'black';
    ctx.font = 'bold 14px monospace';
    ctx.textAlign = 'center';
    ctx.fillText('TOTP QR Code', 100, 90);
    
    ctx.font = '10px monospace';
    ctx.fillText('Scan to import', 100, 110);
    
    // Hide secret by default
    qrSecretText.textContent = '••••••••••••••••';
    qrSecretDisplay.style.display = 'none';
    revealSecretBtn.innerHTML = '<i class="fas fa-eye"></i> Show Secret';
    revealSecretBtn.style.display = 'inline-flex';
    
    let secretRevealed = false;
    
    // Remove existing listener to avoid duplicates
    const newRevealBtn = revealSecretBtn.cloneNode(true);
    revealSecretBtn.parentNode.replaceChild(newRevealBtn, revealSecretBtn);
    
    // Reveal secret button
    newRevealBtn.onclick = () => {
      if (!secretRevealed) {
        qrSecretText.textContent = cleanSecret.match(/.{4}/g).join(' ');
        qrSecretDisplay.style.display = 'block';
        newRevealBtn.innerHTML = '<i class="fas fa-eye-slash"></i> Hide Secret';
        newRevealBtn.style.background = 'var(--warning)';
        secretRevealed = true;
      } else {
        qrSecretText.textContent = '••••••••••••••••';
        qrSecretDisplay.style.display = 'none';
        newRevealBtn.innerHTML = '<i class="fas fa-eye"></i> Show Secret';
        newRevealBtn.style.background = '';
        secretRevealed = false;
      }
    };
    
    // Setup copy button for QR modal
    setupCopyButtons();
    
    // Show modal
    modal.style.display = 'flex';
    
    // Set up close button
    const closeBtn = modal.querySelector('.close-qr-modal');
    if (closeBtn) {
      const newCloseBtn = closeBtn.cloneNode(true);
      closeBtn.parentNode.replaceChild(newCloseBtn, closeBtn);
      
      newCloseBtn.onclick = () => {
        modal.style.display = 'none';
        secretRevealed = false;
      };
    }
    
    // Click outside to close
    modal.onclick = (e) => {
      if (e.target === modal) {
        modal.style.display = 'none';
        secretRevealed = false;
      }
    };
  }

  // =====================================================
  // Vault Functions
  // =====================================================

  // Load entries from storage
  async function loadEntries() {
    try {
      // Only load entries if we're on the vault screen
      const vaultScreen = document.getElementById("screen-vault");
      if (!vaultScreen || !vaultScreen.classList.contains("active")) {
        console.log("Not on vault screen, skipping loadEntries");
        return;
      }
      
      console.log("=== LOAD ENTRIES ===");
      const result = await browser.runtime.sendMessage({ 
        action: "retrieve-local" 
      });
      
      if (result.ok) {
        entries = {};
        console.log(`Received ${result.results.length} entries from background script`);
        
        if (result.results.length === 0) {
          console.log("No entries returned from background.");
        }
        
        result.results.forEach(item => {
          try {
            const entryData = JSON.parse(item.data);
            if (entryData.id) {
              entries[entryData.id] = entryData;
              console.log(`✅ Added entry to cache: ${entryData.id} - ${entryData.website || entryData.title || 'No title'}`);
            } else {
              console.log(`⚠️ Entry without ID:`, entryData);
            }
          } catch (e) {
            console.error("❌ Failed to parse entry:", e, "Raw data:", item.data?.substring(0, 100));
          }
        });
        
        console.log(`📊 Total entries in cache: ${Object.keys(entries).length}`);
        
        // Check if we're still on the vault screen before rendering
        if (vaultScreen.classList.contains("active")) {
          renderEntriesList();
          
          // Update detail view
          if (currentEntryId !== null && entries[currentEntryId]) {
            showEntryDetail(currentEntryId);
          } else {
            showEmptyDetail();
          }
        } else {
          console.log("Left vault screen during load, skipping render");
        }
      } else {
        console.error("❌ Failed to load entries:", result.error);
        showOutput("Error loading entries: " + (result.error || "Unknown error"), true);
      }
    } catch (error) {
      console.error("❌ Error loading entries:", error);
      showOutput("Error loading entries: " + error.message, true);
    }
  }

  // Render entries list in sidebar
  async function renderEntriesList() {
    try {
      // Wait for elements to be ready
      const entriesList = await waitForElement("#entries-list");
      const emptyState = await waitForElement("#empty-state");
      
      console.log(`Rendering ${Object.keys(entries).length} entries`);
      
      if (Object.keys(entries).length === 0) {
        emptyState.style.display = 'block';
        entriesList.innerHTML = '';
        console.log("No entries to display - showing empty state");
      } else {
        emptyState.style.display = 'none';
        entriesList.innerHTML = '';
        
        // Create separate arrays for active and deleted entries
        const activeEntries = [];
        const deletedEntries = [];
        
        Object.entries(entries).forEach(([id, entry]) => {
          if (entry.deleted) {
            deletedEntries.push([id, entry]);
          } else {
            activeEntries.push([id, entry]);
          }
        });
        
        // Sort active entries by modification date (newest first)
        activeEntries.sort(([, a], [, b]) => (b.modified || 0) - (a.modified || 0));
        
        // Sort deleted entries by modification date (newest first)
        deletedEntries.sort(([, a], [, b]) => (b.modified || 0) - (a.modified || 0));
        
        console.log(`Displaying ${activeEntries.length} active and ${deletedEntries.length} deleted entries`);
        
        // Render active entries first
        activeEntries.forEach(([id, entry]) => {
          createEntryElement(entriesList, id, entry, false);
        });
        
        // Add a separator if we have both active and deleted entries
        if (activeEntries.length > 0 && deletedEntries.length > 0) {
          const separator = document.createElement('div');
          separator.className = 'entries-separator';
          separator.innerHTML = '<span>Deleted Entries</span>';
          entriesList.appendChild(separator);
        }
        
        // Render deleted entries
        deletedEntries.forEach(([id, entry]) => {
          createEntryElement(entriesList, id, entry, true);
        });
        
        // If we have entries but none is selected, select the first active one
        if (activeEntries.length > 0 && currentEntryId === null) {
          const firstEntryId = activeEntries[0][0];
          setTimeout(() => {
            const firstElement = document.querySelector(`.entry-item[data-id="${firstEntryId}"]`);
            if (firstElement) {
              firstElement.click();
            }
          }, 50);
        }
      }
    } catch (error) {
      console.error("Error rendering entries list:", error);
    }
  }

  // Show entry detail
  function showEntryDetail(id) {
    if (showingVersionHistory) return;
    
    currentEntryId = id;
    const entry = entries[id];
    
    const emptyDetail = document.getElementById('empty-detail');
    const detailSection = document.getElementById('entry-detail');
    
    if (!emptyDetail || !detailSection) {
      console.error("Detail elements not found");
      return;
    }
    
    if (!entry) {
      console.error(`Entry ${id} not found in cache`);
      return;
    }
    
    emptyDetail.style.display = 'none';
    detailSection.style.display = 'block';
    
    // Populate form fields
    const entryTitle = document.getElementById('entry-title');
    const entryWebsite = document.getElementById('entry-website');
    const entryCategory = document.getElementById('entry-category');
    const entryUsername = document.getElementById('entry-username');
    const entryPassword = document.getElementById('entry-password');
    const entryTotp = document.getElementById('entry-totp');
    const entryNotes = document.getElementById('entry-notes');
    const entryModified = document.getElementById('entry-modified');
    
    if (entryTitle) entryTitle.textContent = entry.title || entry.website || 'Unnamed Entry';
    if (entryWebsite) entryWebsite.value = entry.website || '';
    if (entryCategory) entryCategory.value = entry.category || 'other';
    if (entryUsername) entryUsername.value = entry.username || '';
    if (entryPassword) entryPassword.value = entry.password || '';
    if (entryTotp) entryTotp.value = entry.totp || '';
    if (entryNotes) entryNotes.value = entry.notes || '';
    if (entryModified) entryModified.value = formatDetailedTime(entry.modified);
    
    // Show/hide QR button based on whether we have a TOTP secret
    const showQrBtn = document.getElementById('show-qr');
    if (showQrBtn) {
      if (entry.totp && entry.totp.trim()) {
        showQrBtn.style.display = 'inline-flex';
      } else {
        showQrBtn.style.display = 'none';
      }
    }
    
    // Setup copy buttons and TOTP toggle
    setupCopyButtons();
    setupTOTPToggle();
    
    // Start TOTP display if we have a secret
    if (entry.totp && entry.totp.trim()) {
      startTOTPDisplay(entry.totp);
    } else {
      stopTOTPDisplay();
    }
    
    // Disable form if not editing
    if (!isEditing) {
      disableForm();
    }
    
    // Add version history button if not already present
    const versionBtn = document.getElementById('version-history-btn');
    if (!versionBtn) {
      const entryDetailActions = document.querySelector('.entry-detail-actions');
      if (entryDetailActions) {
        const newVersionBtn = document.createElement('button');
        newVersionBtn.id = 'version-history-btn';
        newVersionBtn.className = 'version-history-btn';
        newVersionBtn.innerHTML = '<i class="fas fa-history"></i> Version History';
        newVersionBtn.onclick = () => showVersionHistory(id);
        entryDetailActions.insertBefore(newVersionBtn, entryDetailActions.firstChild);
      }
    }
    
    // Show/hide delete button based on entry state
    const deleteBtn = document.getElementById('delete-entry');
    if (deleteBtn) {
      if (entry.deleted) {
        deleteBtn.innerHTML = '<i class="fas fa-undo"></i> Restore';
        deleteBtn.style.color = 'var(--success)';
      } else {
        deleteBtn.innerHTML = '<i class="fas fa-trash"></i> Delete';
        deleteBtn.style.color = 'var(--danger)';
      }
    }
  }

  // Show empty detail view
  function showEmptyDetail() {
    const emptyDetail = document.getElementById('empty-detail');
    const detailSection = document.getElementById('entry-detail');
    
    if (emptyDetail && detailSection) {
      emptyDetail.style.display = 'block';
      detailSection.style.display = 'none';
    }
    currentEntryId = null;
    stopTOTPDisplay();
  }

  // Enable form for editing
  function enableForm() {
    isEditing = true;
    const editBtn = document.getElementById('edit-entry');
    const saveBtn = document.getElementById('save-entry');
    
    if (editBtn && saveBtn) {
      editBtn.style.display = 'none';
      saveBtn.style.display = 'inline-flex';
    }
    
    const form = document.getElementById('entry-form');
    if (form) {
      form.querySelectorAll('input, select, textarea').forEach(input => {
        input.disabled = false;
      });
    }
    
    console.log("Form enabled for editing");
  }

  // Disable form
  function disableForm() {
    isEditing = false;
    const editBtn = document.getElementById('edit-entry');
    const saveBtn = document.getElementById('save-entry');
    
    if (editBtn && saveBtn) {
      editBtn.style.display = 'inline-flex';
      saveBtn.style.display = 'none';
    }
    
    const form = document.getElementById('entry-form');
    if (form) {
      form.querySelectorAll('input, select, textarea').forEach(input => {
        input.disabled = true;
      });
    }
    
    console.log("Form disabled");
  }

  // Save entry
  async function saveEntry() {
    if (currentEntryId === null) {
      console.error("No current entry ID");
      showOutput("Error: No entry selected", true);
      return;
    }
    
    // Ensure the entry has an ID
    const entryId = currentEntryId;
    
    const entryWebsite = document.getElementById('entry-website');
    const entryCategory = document.getElementById('entry-category');
    const entryUsername = document.getElementById('entry-username');
    const entryPassword = document.getElementById('entry-password');
    const entryTotp = document.getElementById('entry-totp');
    const entryNotes = document.getElementById('entry-notes');
    
    if (!entryWebsite || !entryCategory || !entryUsername || !entryPassword || !entryTotp || !entryNotes) {
      console.error("Form elements not found");
      showOutput("Error: Form not ready", true);
      return;
    }
    
    const entry = {
      id: entryId,
      website: entryWebsite.value,
      category: entryCategory.value,
      username: entryUsername.value,
      password: entryPassword.value,
      totp: entryTotp.value,
      notes: entryNotes.value,
      modified: Date.now(),
      title: entryWebsite.value || 'Unnamed Entry'
    };
    
    // Check if this is a new entry or edit
    const isNewEntry = !entries[entryId];
    
    console.log(`Saving entry: ${entryId}, isNew: ${isNewEntry}`);
    
    try {
      const result = await browser.runtime.sendMessage({
        action: "store",
        data: JSON.stringify(entry),
        entryId: entryId,
        isNewEntry: isNewEntry
      });
      
      if (result.ok) {
        // Update local entries cache
        entries[entryId] = entry;
        
        console.log(`Entry saved successfully at index ${result.index}`);
        
        // Force re-render of entries list
        renderEntriesList();
        
        // Highlight the saved entry
        const savedEntryElement = document.querySelector(`.entry-item[data-id="${entryId}"]`);
        if (savedEntryElement) {
          document.querySelectorAll('.entry-item').forEach(el => el.classList.remove('active'));
          savedEntryElement.classList.add('active');
        }
        
        showEntryDetail(entryId);
        disableForm();
        showOutput("Entry saved successfully!");
        
        // Notify background script that UI needs updating
        try {
          await browser.runtime.sendMessage({ action: "ui-updated" });
        } catch (e) {
          console.log("UI update notification failed:", e);
        }
      } else {
        console.error("Save failed:", result.error);
        showOutput("Error saving entry: " + (result.error || "Unknown error"), true);
      }
    } catch (error) {
      console.error("Error saving entry:", error);
      showOutput("Error saving entry: " + error.message, true);
    }
  }

  // Delete/Restore entry
  async function toggleEntryState() {
    if (currentEntryId === null) return;
    
    const entry = entries[currentEntryId];
    if (!entry) return;
    
    const action = entry.deleted ? 'restore' : 'delete';
    const confirmMessage = entry.deleted 
      ? "Are you sure you want to restore this entry?"
      : "Are you sure you want to delete this entry?";
    
    if (!confirm(confirmMessage)) return;
    
    const updatedEntry = {
      ...entry,
      deleted: !entry.deleted,
      modified: Date.now()
    };
    
    try {
      const result = await browser.runtime.sendMessage({
        action: "store",
        data: JSON.stringify(updatedEntry),
        entryId: currentEntryId,
        isNewEntry: false
      });
      
      if (result.ok) {
        // Update local cache
        entries[currentEntryId] = updatedEntry;
        
        // Update UI
        showEntryDetail(currentEntryId);
        renderEntriesList();
        
        const actionText = entry.deleted ? 'restored' : 'deleted';
        showOutput(`Entry ${actionText} successfully!`);
        
        // Notify background script that UI needs updating
        try {
          await browser.runtime.sendMessage({ action: "ui-updated" });
        } catch (e) {
          console.log("UI update notification failed:", e);
        }
      }
    } catch (error) {
      showOutput("Error updating entry: " + error.message, true);
    }
  }

  // =====================================================
  // Version History Functions
  // =====================================================
  async function showVersionHistory(entryId) {
    try {
      showingVersionHistory = true;
      
      // Get versions from background
      const result = await browser.runtime.sendMessage({
        action: "get-version-history",
        entryId: entryId
      });
      
      if (!result.ok) {
        showOutput("Error loading version history: " + result.error, true);
        showingVersionHistory = false;
        return;
      }
      
      currentVersions = result.versions;
      
      if (currentVersions.length === 0) {
        showOutput("No version history available for this entry", false);
        showingVersionHistory = false;
        return;
      }
      
      // Show the modal
      const modal = document.getElementById('version-history-modal');
      const versionList = document.getElementById('version-list');
      
      if (!modal || !versionList) {
        showOutput("Version history modal not found", true);
        showingVersionHistory = false;
        return;
      }
      
      // Populate version list
      versionList.innerHTML = '';
      currentVersions.forEach((version, i) => {
        const versionElement = document.createElement('div');
        versionElement.className = `version-item ${version.data.deleted ? 'deleted' : ''} ${i === 0 ? 'active' : ''}`;
        versionElement.dataset.index = i;
        
        versionElement.innerHTML = `
          <div class="version-item-header">
            <div class="version-title">
              <strong>${formatDetailedTime(version.timestamp)}</strong>
              ${version.data.deleted ? '<span style="color: var(--danger); margin-left: 10px;"><i class="fas fa-trash"></i> Deleted</span>' : ''}
              ${i === 0 ? '<span style="color: var(--success); margin-left: 10px;"><i class="fas fa-star"></i> Current</span>' : ''}
            </div>
            <div class="version-time">
              Block: ${version.blockHeight || 'Unknown'}
            </div>
          </div>
          <div class="version-preview">
            <strong>${version.data.website || version.data.title || 'No title'}</strong>
            ${version.data.username ? ` · ${version.data.username}` : ''}
            ${version.data.category ? ` · ${version.data.category}` : ''}
          </div>
        `;
        
        versionElement.addEventListener('click', () => {
          document.querySelectorAll('.version-item').forEach(el => el.classList.remove('active'));
          versionElement.classList.add('active');
        });
        
        versionList.appendChild(versionElement);
      });
      
      // Show modal
      modal.style.display = 'flex';
      
      // Set up close button
      const closeBtn = modal.querySelector('.close-version-history');
      if (closeBtn) {
        const newCloseBtn = closeBtn.cloneNode(true);
        closeBtn.parentNode.replaceChild(newCloseBtn, closeBtn);
        
        newCloseBtn.onclick = () => {
          modal.style.display = 'none';
          showingVersionHistory = false;
        };
      }
      
      // Set up view version button
      const viewBtn = document.getElementById('view-version');
      if (viewBtn) {
        const newViewBtn = viewBtn.cloneNode(true);
        viewBtn.parentNode.replaceChild(newViewBtn, viewBtn);
        
        newViewBtn.onclick = () => {
          const selectedItem = modal.querySelector('.version-item.active');
          if (selectedItem) {
            const index = parseInt(selectedItem.dataset.index);
            if (index >= 0 && index < currentVersions.length) {
              showVersionDetail(currentVersions[index].data);
            }
          }
        };
      }
      
      // Set up restore version button
      const restoreBtn = document.getElementById('restore-version');
      if (restoreBtn) {
        const newRestoreBtn = restoreBtn.cloneNode(true);
        restoreBtn.parentNode.replaceChild(newRestoreBtn, restoreBtn);
        
        newRestoreBtn.onclick = async () => {
          const selectedItem = modal.querySelector('.version-item.active');
          if (selectedItem) {
            const index = parseInt(selectedItem.dataset.index);
            if (index > 0 && index < currentVersions.length) {
              const version = currentVersions[index];
              if (confirm(`Restore version from ${formatDetailedTime(version.timestamp)}? This will create a new version with this data.`)) {
                try {
                  // Create a new entry based on the selected version
                  const restoredEntry = {
                    ...version.data,
                    modified: Date.now()
                  };
                  
                  // Remove deleted flag if it exists
                  delete restoredEntry.deleted;
                  
                  // Save as current entry
                  const result = await browser.runtime.sendMessage({
                    action: "store",
                    data: JSON.stringify(restoredEntry),
                    entryId: entryId,
                    isNewEntry: false
                  });
                  
                  if (result.ok) {
                    // Update local cache
                    entries[entryId] = restoredEntry;
                    
                    // Update UI
                    showEntryDetail(entryId);
                    renderEntriesList();
                    
                    // Close modal
                    modal.style.display = 'none';
                    showingVersionHistory = false;
                    
                    showOutput("Version restored successfully!");
                  }
                } catch (error) {
                  showOutput("Error restoring version: " + error.message, true);
                }
              }
            } else {
              showOutput("Cannot restore the current version", true);
            }
          }
        };
      }
      
      // Click outside to close
      modal.onclick = (e) => {
        if (e.target === modal) {
          modal.style.display = 'none';
          showingVersionHistory = false;
        }
      };
      
    } catch (error) {
      console.error("Error showing version history:", error);
      showOutput("Error loading version history", true);
      showingVersionHistory = false;
    }
  }

  function showVersionDetail(versionData) {
    const modal = document.getElementById('version-detail-modal');
    const content = document.getElementById('version-detail-content');
    
    if (!modal || !content) {
      showOutput("Version detail modal not found", true);
      return;
    }
    
    content.innerHTML = `
      <div style="margin-bottom: 15px;">
        <strong>Website:</strong> ${versionData.website || 'N/A'}
      </div>
      <div style="margin-bottom: 15px;">
        <strong>Username:</strong> ${versionData.username || 'N/A'}
      </div>
      <div style="margin-bottom: 15px;">
        <strong>Category:</strong> ${versionData.category || 'other'}
      </div>
      <div style="margin-bottom: 15px;">
        <strong>Password:</strong> ${versionData.password ? '••••••••' : 'N/A'}
      </div>
      <div style="margin-bottom: 15px;">
        <strong>TOTP:</strong> ${versionData.totp ? '••••••' : 'N/A'}
      </div>
      <div style="margin-bottom: 15px;">
        <strong>Notes:</strong><br>
        ${versionData.notes || 'No notes'}
      </div>
      <div style="color: var(--text-secondary); font-size: 12px;">
        <i class="fas fa-clock"></i> Modified: ${formatDetailedTime(versionData.modified)}
      </div>
    `;
    
    modal.style.display = 'flex';
    
    // Set up close button
    const closeBtn = modal.querySelector('.close-version-detail');
    if (closeBtn) {
      const newCloseBtn = closeBtn.cloneNode(true);
      closeBtn.parentNode.replaceChild(newCloseBtn, closeBtn);
      
      newCloseBtn.onclick = () => {
        modal.style.display = 'none';
      };
    }
    
    // Click outside to close
    modal.onclick = (e) => {
      if (e.target === modal) {
        modal.style.display = 'none';
      }
    };
  }

  // =====================================================
  // Event Listeners Setup
  // =====================================================

  // Initialize app based on vault state
  try {
    const { vaultInitialized } = await browser.storage.local.get("vaultInitialized");
    if (!vaultInitialized) {
      show("screen-entry");
    } else {
      show("screen-unlock");
    }
  } catch (error) {
    console.error("Failed to check vault state:", error);
    show("screen-entry");
  }

  // Entry screen buttons
  const btnLogin = document.getElementById("btn-login");
  if (btnLogin) {
    btnLogin.onclick = () => show("screen-login");
  }

  const btnNew = document.getElementById("btn-new");
  if (btnNew) {
    btnNew.onclick = async () => {
      generatedMnemonic = await generateBip39Mnemonic();
      const generatedMnemonicField = document.getElementById("generated-mnemonic");
      if (generatedMnemonicField) {
        generatedMnemonicField.value = generatedMnemonic;
      }
      show("screen-new-mnemonic");
    };
  }

  // Password validation feedback
  const newPasswordInput = document.getElementById("new-password");
  if (newPasswordInput) {
    newPasswordInput.addEventListener("input", function() {
      const issues = validatePassword(this.value);
      const rulesList = document.getElementById("password-rules");
      
      if (!rulesList) return;
      
      rulesList.innerHTML = '';
      if (issues.length === 0) {
        rulesList.innerHTML = '<li style="color: var(--success);"><i class="fas fa-check"></i> Strong password!</li>';
      } else {
        issues.forEach(issue => {
          const li = document.createElement('li');
          li.innerHTML = `<i class="fas fa-times"></i> ${issue}`;
          li.style.color = 'var(--danger)';
          rulesList.appendChild(li);
        });
      }
    });
  }

  // New user flow
  const mnemonicSavedBtn = document.getElementById("mnemonic-saved");
  if (mnemonicSavedBtn) {
    mnemonicSavedBtn.onclick = () => show("screen-new-password");
  }
  
  const createVaultBtn = document.getElementById("create-vault");
  if (createVaultBtn) {
    createVaultBtn.onclick = async () => {
      const newPassword = document.getElementById("new-password");
      const newPasswordConfirm = document.getElementById("new-password-confirm");
      
      if (!newPassword || !newPasswordConfirm) return;
      
      const p1 = newPassword.value;
      const p2 = newPasswordConfirm.value;

      if (!p1 || p1 !== p2) {
        showOutput("Passwords do not match", true);
        return;
      }

      const issues = validatePassword(p1);
      if (issues.length > 0) {
        showOutput("Password must contain:\n- " + issues.join("\n- "), true);
        return;
      }

      try {
        await browser.runtime.sendMessage({
          action: "init-vault",
          mnemonic: generatedMnemonic,
          password: p1
        });
        show("screen-vault");
      } catch (e) {
        showOutput(e.toString(), true);
      }
    };
  }

  // Login (mnemonic + password)
  const loginUnlockBtn = document.getElementById("login-unlock");
  if (loginUnlockBtn) {
    loginUnlockBtn.onclick = async () => {
      const loginMnemonic = document.getElementById("login-mnemonic");
      const loginPassword = document.getElementById("login-password");
      
      if (!loginMnemonic || !loginPassword) return;
      
      const mnemonic = loginMnemonic.value.trim();
      const error = await validateMnemonicChecksum(mnemonic);
      if (error) {
        showOutput(error, true);
        return;
      }

      try {
        await browser.runtime.sendMessage({
          action: "unlock",
          mnemonic,
          password: loginPassword.value
        });
        show("screen-vault");
      } catch (e) {
        showOutput(e.toString(), true);
      }
    };
  }

  // Unlock (password only)
  const unlockBtn = document.getElementById("unlock-btn");
  if (unlockBtn) {
    unlockBtn.onclick = async () => {
      const unlockPassword = document.getElementById("unlock-password");
      if (!unlockPassword) return;
      
      try {
        await browser.runtime.sendMessage({
          action: "unlock",
          password: unlockPassword.value
        });
        show("screen-vault");
      } catch (e) {
        showOutput(e.toString(), true);
      }
    };
  }

  // Vault actions
  const addEntryBtn = document.getElementById("add-entry");
  if (addEntryBtn) {
    addEntryBtn.onclick = () => {
      console.log("Add entry button clicked");
      
      // Create new entry with proper ID
      const newId = generateEntryId();
      currentEntryId = newId;
      
      // Show detail section and hide empty state
      const emptyDetail = document.getElementById('empty-detail');
      const detailSection = document.getElementById('entry-detail');
      
      if (emptyDetail && detailSection) {
        emptyDetail.style.display = 'none';
        detailSection.style.display = 'block';
      }
      
      // Reset form fields
      const form = document.getElementById('entry-form');
      if (form) {
        form.reset();
      }
      
      // Set default category
      const categorySelect = document.getElementById('entry-category');
      if (categorySelect) {
        categorySelect.value = 'other';
      }
      
      // Set default title
      const entryTitle = document.getElementById('entry-title');
      if (entryTitle) {
        entryTitle.textContent = 'New Entry';
      }
      
      const entryModified = document.getElementById('entry-modified');
      if (entryModified) {
        entryModified.value = new Date().toLocaleString();
      }
      
      // Enable editing mode
      enableForm();
      
      // Create temporary entry for sidebar display
      const tempEntry = {
        id: newId,
        website: '',
        category: 'other',
        username: '',
        title: 'New Entry',
        modified: Date.now(),
        password: '',
        totp: '',
        notes: ''
      };
      
      // Add to entries cache
      entries[newId] = tempEntry;
      
      // Re-render entries list
      renderEntriesList();
      
      // Setup copy buttons for the new entry
      setupCopyButtons();
      setupTOTPToggle();
      
      // Focus on the first field
      setTimeout(() => {
        const websiteField = document.getElementById('entry-website');
        if (websiteField) {
          websiteField.focus();
        }
      }, 100);
    };
  }

  const editEntryBtn = document.getElementById("edit-entry");
  if (editEntryBtn) {
    editEntryBtn.onclick = enableForm;
  }

  const saveEntryBtn = document.getElementById("save-entry");
  if (saveEntryBtn) {
    saveEntryBtn.onclick = saveEntry;
  }

  const deleteEntryBtn = document.getElementById("delete-entry");
  if (deleteEntryBtn) {
    deleteEntryBtn.onclick = toggleEntryState;
  }

  // Manual sync with immediate UI refresh
  const manualSyncBtn = document.getElementById("manual-sync");
  if (manualSyncBtn) {
    manualSyncBtn.onclick = async () => {
      try {
        // Show loading state
        const syncBtn = document.getElementById("manual-sync");
        const originalHTML = syncBtn.innerHTML;
        syncBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Syncing...';
        syncBtn.disabled = true;
        
        console.log("Starting manual sync...");
        const result = await browser.runtime.sendMessage({ action: "retrieve-graphql" });
        
        // Restore button
        syncBtn.innerHTML = originalHTML;
        syncBtn.disabled = false;
        
        console.log("Sync result:", result);
        
        if (result && result.ok) {
          if (result.syncSuccessful && result.results && result.results.length > 0) {
            // Force immediate refresh from storage
            await loadEntries();
            showOutput(`✅ ${result.message}`);
          } else if (result.message) {
            // Show the message from the sync
            showOutput(result.message);
          } else {
            showOutput("No new entries found on Arweave.");
          }
        } else {
          showOutput("Sync failed: " + (result.error || result.message || "Unknown error"), true);
        }
      } catch (e) {
        console.error("Sync error:", e);
        showOutput("Sync error: " + e.toString(), true);
        
        // Restore button on error too
        const syncBtn = document.getElementById("manual-sync");
        if (syncBtn) {
          syncBtn.innerHTML = '<i class="fas fa-sync-alt"></i> Sync';
          syncBtn.disabled = false;
        }
      }
    };
  }

  const lockBtn = document.getElementById("lock");
  if (lockBtn) {
    lockBtn.onclick = () => {
      // Stop TOTP display
      stopTOTPDisplay();
      
      browser.runtime.sendMessage({ action: "lock" });
      show("screen-unlock");
    };
  }

  // Debug storage button
  const debugStorageBtn = document.getElementById("debug-storage");
  if (debugStorageBtn) {
    debugStorageBtn.onclick = async () => {
      try {
        console.log("=== DEBUG STORAGE ===");
        
        // Get vault info
        const vaultInfo = await browser.runtime.sendMessage({ action: "get-vault-info" });
        console.log("Vault Info:", vaultInfo);
        
        // Get raw storage
        const storage = await browser.storage.local.get();
        console.log("Raw Storage:", {
          currentIndex: storage.currentIndex,
          entriesCount: Object.keys(storage.entries || {}).length,
          versionSets: Object.keys(storage.entryVersions || {}).length,
          entries: storage.entries
        });
        
        // Show current cache
        console.log("Current cache:", {
          entriesCount: Object.keys(entries).length,
          entries: entries
        });
        
        showOutput("Debug info logged to console", false);
      } catch (e) {
        console.error("Debug error:", e);
        showOutput("Debug failed: " + e.message, true);
      }
    };
  }

  // Password toggle
  const togglePasswordBtn = document.getElementById("toggle-password");
  if (togglePasswordBtn) {
    togglePasswordBtn.onclick = function() {
      const passwordField = document.getElementById("entry-password");
      if (!passwordField) return;
      
      const icon = this.querySelector("i");
      
      if (passwordField.type === "password") {
        passwordField.type = "text";
        if (icon) icon.className = "fas fa-eye-slash";
      } else {
        passwordField.type = "password";
        if (icon) icon.className = "fas fa-eye";
      }
    };
  }

  // Generate password
  const generatePasswordBtn = document.getElementById("generate-password");
  if (generatePasswordBtn) {
    generatePasswordBtn.onclick = () => {
      const passwordField = document.getElementById("entry-password");
      if (passwordField) {
        passwordField.value = generatePassword();
      }
    };
  }

  // TOTP functionality
  const showQRBtn = document.getElementById("show-qr");
  if (showQRBtn) {
    showQRBtn.onclick = () => {
      const totpField = document.getElementById("entry-totp");
      const websiteField = document.getElementById("entry-website");
      const usernameField = document.getElementById("entry-username");
      
      if (totpField && totpField.value.trim()) {
        const website = websiteField ? websiteField.value : '';
        const username = usernameField ? usernameField.value : '';
        const accountName = username ? `${username}@${website}` : website;
        
        generateQRCodeFromSecret(totpField.value, accountName, 'Arweave Vault');
      } else {
        showOutput("Please enter a TOTP secret first", true);
      }
    };
  }
  
  // TOTP field change listener
  const totpField = document.getElementById("entry-totp");
  if (totpField) {
    totpField.addEventListener('input', function() {
      const showQrBtn = document.getElementById("show-qr");
      const secret = this.value.trim();
      
      if (showQrBtn) {
        if (secret) {
          showQrBtn.style.display = 'inline-flex';
          startTOTPDisplay(secret);
        } else {
          showQrBtn.style.display = 'none';
          stopTOTPDisplay();
        }
      }
    });
  }

  // Search functionality
  const searchBox = document.querySelector(".search-box");
  if (searchBox) {
    searchBox.addEventListener("input", function(e) {
      const searchTerm = e.target.value.toLowerCase();
      
      document.querySelectorAll(".entry-item").forEach(item => {
        const titleEl = item.querySelector(".entry-item-title");
        const usernameEl = item.querySelector(".entry-item-username");
        
        if (titleEl && usernameEl) {
          const title = titleEl.textContent.toLowerCase();
          const username = usernameEl.textContent.toLowerCase();
          
          if (title.includes(searchTerm) || username.includes(searchTerm)) {
            item.style.display = "flex";
          } else {
            item.style.display = "none";
          }
        }
      });
    });
  }

  // Listen for storage changes from background
  browser.runtime.onMessage.addListener((message) => {
    if (message.action === "storage-updated") {
      console.log("Background notified of storage update:", message.type, "entryId:", message.entryId);
      
      // Only refresh if we're on the vault screen
      const vaultScreen = document.getElementById("screen-vault");
      if (vaultScreen && vaultScreen.classList.contains("active")) {
        // Refresh entries when storage changes
        loadEntries();
      } else {
        console.log("Received storage update but not on vault screen, ignoring");
      }
    }
  });

  // Listen for storage changes directly
  browser.storage.onChanged.addListener((changes, namespace) => {
    if (namespace === 'local' && (changes.entries || changes.currentIndex || changes.entryVersions)) {
      console.log("Storage changed detected");
      
      // Only refresh if we're on the vault screen
      const vaultScreen = document.getElementById("screen-vault");
      if (vaultScreen && vaultScreen.classList.contains("active")) {
        console.log("Refreshing entries due to storage change");
        loadEntries();
      }
    }
  });
}
