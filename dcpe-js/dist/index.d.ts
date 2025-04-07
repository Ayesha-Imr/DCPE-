/**
 * Distance Comparison Preserving Encryption for JavaScript
 * TypeScript definitions
 */

// Main DCPE class
export class DCPE {
  /**
   * Create a new DCPE instance
   * @param config - Configuration options
   */
  constructor(config?: {
    keyProvider?: string;
    keyProviderConfig?: Record<string, any>;
    vectorConfig?: Record<string, any>;
  });

  /**
   * Generate encryption keys
   * @param options - Options for key generation
   */
  generateKeys(options?: {
    approximationFactor?: number;
  }): Promise<Buffer>;

  /**
   * Set encryption keys
   * @param encryptionKeys - Encryption keys to set
   */
  setKeys(encryptionKeys: Buffer | object): void;

  /**
   * Encrypt a vector using DCPE
   * @param vector - Vector to encrypt
   * @param options - Encryption options
   */
  encryptVector(vector: number[], options?: Record<string, any>): number[];

  /**
   * Decrypt a vector using DCPE
   * @param encryptedVector - Encrypted vector
   * @param options - Decryption options
   */
  decryptVector(encryptedVector: number[], options?: Record<string, any>): number[];

  /**
   * Encrypt text using AES-GCM
   * @param text - Text to encrypt
   * @param options - Encryption options
   */
  encryptText(text: string, options?: Record<string, any>): {
    ciphertext: Buffer;
    iv: Buffer;
    tag: Buffer;
  };

  /**
   * Decrypt text using AES-GCM
   * @param encryptedText - Encrypted text
   * @param options - Decryption options
   */
  decryptText(encryptedText: {
    ciphertext: Buffer;
    iv: Buffer;
    tag: Buffer;
  }, options?: Record<string, any>): string;

  /**
   * Encrypt metadata field using deterministic encryption
   * @param value - Value to encrypt
   * @param options - Encryption options
   */
  encryptMetadata(value: string | number, options?: Record<string, any>): Buffer;

  /**
   * Decrypt metadata field
   * @param encryptedValue - Encrypted value
   * @param options - Decryption options
   */
  decryptMetadata(encryptedValue: Buffer, options?: Record<string, any>): string | number;
}

// Crypto module
export namespace crypto {
  export function encryptVector(vector: number[], key: Buffer, options?: Record<string, any>): number[];
  export function decryptVector(encryptedVector: number[], key: Buffer, options?: Record<string, any>): number[];
  // Additional crypto functions...
}

// Key Provider module
export namespace keyProvider {
  export class KeyProvider {
    getKey(keyId?: string): Promise<Buffer>;
    storeKey(keyMaterial: Buffer, keyId?: string): Promise<string>;
  }

  export class LocalKeyProvider extends KeyProvider {
    constructor(config?: Record<string, any>);
    setKeys(encryptionKeys: Buffer | object): void;
    getKeys(): Buffer;
  }

  export class ClientKeyProvider extends KeyProvider {
    constructor(keyStore: Record<string, any>);
  }
}

// Keys module
export namespace keys {
  export class EncryptionKey {
    constructor(keyBytes: Buffer);
    getBytes(): Buffer;
    equals(other: EncryptionKey): boolean;
    toString(): string;
  }

  export class ScalingFactor {
    constructor(factor: number);
    getFactor(): number;
    equals(other: ScalingFactor): boolean;
    toString(): string;
  }

  export class VectorEncryptionKey {
    constructor(scalingFactor: ScalingFactor, key: EncryptionKey);
    static deriveFromSecret(secret: Buffer, tenantId: string, derivationPath: string): VectorEncryptionKey;
    static unsafeBytesToKey(keyBytes: Buffer): VectorEncryptionKey;
    equals(other: VectorEncryptionKey): boolean;
    toString(): string;
  }

  export function generateRandomKey(): EncryptionKey;
  export function generateEncryptionKeys(options?: { approximationFactor?: number }): Promise<Buffer>;
}

// RAG Encryption module
export namespace ragEncryption {
  export class RagEncryptionClient {
    constructor(encryptionKey?: Buffer, approximationFactor?: number, keyProvider?: keyProvider.KeyProvider, keyId?: string);
    static create(encryptionKey?: Buffer, approximationFactor?: number, keyProvider?: keyProvider.KeyProvider, keyId?: string): Promise<RagEncryptionClient>;
    encryptVector(plaintextVector: number[]): [number[], Buffer];
    decryptVector(encryptedVector: number[], pairedIclInfo: Buffer): number[];
    encryptText(plaintext: string): { ciphertext: Buffer; iv: Buffer; tag: Buffer };
    decryptText(ciphertext: Buffer, iv: Buffer, tag: Buffer): string;
    encryptDeterministicText(plaintext: string): Buffer;
    decryptDeterministicText(encryptedData: Buffer): string;
  }

  export function encryptText(text: string, keys: Buffer, options?: Record<string, any>): { ciphertext: Buffer; iv: Buffer; tag: Buffer };
  export function decryptText(encryptedText: { ciphertext: Buffer; iv: Buffer; tag: Buffer }, keys: Buffer, options?: Record<string, any>): string;
  export function encryptMetadataField(value: string | number, keys: Buffer, options?: Record<string, any>): Buffer;
  export function decryptMetadataField(encryptedValue: Buffer, keys: Buffer, options?: Record<string, any>): string | number;
}

// Exceptions module
export namespace exceptions {
  export class InvalidKeyError extends Error {}
  export class InvalidInputError extends Error {}
  export class DecryptError extends Error {}
  // Additional exceptions...
}

// Configuration utilities
export namespace configUtils {
  export function validateConfig(config: Record<string, any>, schema: {
    required?: string[];
    properties?: Record<string, any>;
  }): Record<string, any>;

  export function createSchema(properties: Record<string, any>, required?: string[]): {
    properties: Record<string, any>;
    required: string[];
  };
}

// Version information
export const VERSION: string;

// BaseAdapter export (detailed in separate file)
export { BaseAdapter } from './adapters';