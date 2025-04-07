/**
 * DCPE-JS - Distance Comparison Preserving Encryption for JavaScript
 * Main entry point for the library
 */

// Import core modules
import * as crypto from './crypto/index.js';
import * as exceptions from './exceptions/index.js';
import * as headers from './headers/index.js';
import * as keyProvider from './key_provider/index.js';
import * as keys from './keys/index.js';
import * as ragEncryption from './rag_encryption/index.js';
import * as configUtils from './utils/config-validator.js';
import { BaseAdapter } from './adapters/index.js';

// Import and export the main DCPE class
import DCPE from './dcpe.js';
export { DCPE };

// Export individual modules
export {
  crypto,
  exceptions,
  headers,
  keyProvider,
  keys,
  ragEncryption,
  configUtils,
  BaseAdapter
};

// Export version
export const VERSION = '0.1.0';