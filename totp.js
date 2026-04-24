// totp.js - TOTP implementation
// Based on RFC 6238 (TOTP) and RFC 4226 (HOTP)

class TOTP {
  // Generate a TOTP code from a secret
  static generate(secret, options = {}) {
    const {
      digits = 6,
      period = 30,
      timestamp = Date.now(),
      algorithm = 'SHA-1'
    } = options;
    
    // Decode the secret (can be base32 or plain text)
    const key = this.decodeSecret(secret);
    
    // Calculate counter based on current time
    const counter = Math.floor(timestamp / 1000 / period);
    
    // Generate HOTP code
    return this.generateHOTP(key, counter, digits, algorithm);
  }
  
  // Decode secret (handles base32 and plain text)
  static decodeSecret(secret) {
    secret = secret.replace(/\s/g, '').toUpperCase();
    
    // Check if it looks like base32 (only A-Z2-7 characters)
    if (/^[A-Z2-7]+=*$/.test(secret)) {
      return this.base32ToBytes(secret);
    }
    
    // Otherwise treat as plain text (UTF-8)
    return new TextEncoder().encode(secret);
  }
  
  // Base32 decoding
  static base32ToBytes(base32) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    base32 = base32.toUpperCase().replace(/=+$/, '');
    
    const bytes = [];
    let buffer = 0;
    let bitsLeft = 0;
    
    for (let i = 0; i < base32.length; i++) {
      const char = base32.charAt(i);
      const value = alphabet.indexOf(char);
      
      if (value === -1) {
        throw new Error('Invalid base32 character: ' + char);
      }
      
      buffer = (buffer << 5) | value;
      bitsLeft += 5;
      
      if (bitsLeft >= 8) {
        bytes.push((buffer >> (bitsLeft - 8)) & 0xff);
        bitsLeft -= 8;
      }
    }
    
    return new Uint8Array(bytes);
  }
  
  // Generate HOTP code
  static async generateHOTP(key, counter, digits, algorithm) {
    // Convert counter to 8-byte array (big-endian)
    const counterBytes = new Uint8Array(8);
    for (let i = 7; i >= 0; i--) {
      counterBytes[i] = counter & 0xff;
      counter = counter >> 8;
    }
    
    // Generate HMAC
    const hmac = await this.generateHMAC(key, counterBytes, algorithm);
    
    // Dynamic truncation
    const offset = hmac[hmac.length - 1] & 0x0f;
    const binary = 
      ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff);
    
    const otp = binary % Math.pow(10, digits);
    
    // Pad with leading zeros
    return otp.toString().padStart(digits, '0');
  }
  
  // Generate HMAC
  static async generateHMAC(key, message, algorithm) {
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'HMAC', hash: algorithm },
      false,
      ['sign']
    );
    
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, message);
    return new Uint8Array(signature);
  }
  
  // Validate a TOTP code
  static async validate(secret, code, options = {}) {
    const {
      digits = 6,
      period = 30,
      window = 1, // Allow codes from previous/next windows
      timestamp = Date.now()
    } = options;
    
    for (let i = -window; i <= window; i++) {
      const testTimestamp = timestamp + (i * period * 1000);
      const testCode = await this.generate(secret, {
        ...options,
        timestamp: testTimestamp,
        digits
      });
      
      if (testCode === code) {
        return true;
      }
    }
    
    return false;
  }
  
  // Get time remaining until next code
  static getTimeRemaining(period = 30) {
    const now = Date.now();
    const seconds = Math.floor(now / 1000);
    return period - (seconds % period);
  }
  
  // Generate QR Code URL for Google Authenticator
  static generateQRCodeURL(secret, accountName, issuer) {
    const encodedIssuer = encodeURIComponent(issuer || 'Arweave Vault');
    const encodedAccount = encodeURIComponent(accountName || '');
    const encodedSecret = encodeURIComponent(secret.replace(/\s/g, ''));
    
    return `otpauth://totp/${encodedIssuer}:${encodedAccount}?secret=${encodedSecret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=6&period=30`;
  }
  
  // Check if a string is a valid base32 TOTP secret
  static isValidSecret(secret) {
    if (!secret || typeof secret !== 'string') return false;
    
    const cleanSecret = secret.replace(/\s/g, '').toUpperCase();
    const base32Regex = /^[A-Z2-7]+=*$/;
    
    return base32Regex.test(cleanSecret);
  }
  
  // Format secret for display (with spaces every 4 characters)
  static formatSecret(secret) {
    if (!secret) return '';
    
    const cleanSecret = secret.replace(/\s/g, '').toUpperCase();
    return cleanSecret.match(/.{1,4}/g).join(' ');
  }
}

// Export for browser
if (typeof window !== 'undefined') {
  window.TOTP = TOTP;
}

// Export for Node.js/CommonJS
if (typeof module !== 'undefined' && module.exports) {
  module.exports = TOTP;
}
