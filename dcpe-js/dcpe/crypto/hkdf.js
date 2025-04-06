import crypto from 'crypto';

/**
 * HMAC-based Key Derivation Function implementation.
 * 
 * @param {Buffer} ikm - Input key material
 * @param {number} length - The desired length of the derived key
 * @param {Buffer} salt - Optional salt value (recommended)
 * @param {Buffer} info - Optional context and application specific information
 * @returns {Buffer} The derived key
 */
function hkdf(ikm, length, salt, info) {
    if (!Buffer.isBuffer(ikm)) {
        throw new TypeError('Input key material must be a Buffer');
    }
    
    // Default values
    salt = salt || Buffer.alloc(0);
    info = info || Buffer.alloc(0);
    
    // Step 1: Extract
    const prk = crypto.createHmac('sha256', salt).update(ikm).digest();
    
    // Step 2: Expand
    const result = Buffer.alloc(length);
    let previous = Buffer.alloc(0);
    let resultPosition = 0;
    const hashLen = 32; // SHA-256 hash length
    
    for (let i = 1; resultPosition < length; i++) {
        const hmac = crypto.createHmac('sha256', prk);
        hmac.update(Buffer.concat([previous, info, Buffer.from([i])]));
        
        const next = hmac.digest();
        const remainder = Math.min(length - resultPosition, hashLen);
        
        next.copy(result, resultPosition, 0, remainder);
        previous = next;
        resultPosition += remainder;
    }
    
    return result;
}

export { hkdf };