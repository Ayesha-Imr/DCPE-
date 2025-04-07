# DCPE-JS

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![npm version](https://badge.fury.io/js/dcpe-js.svg)](https://badge.fury.io/js/dcpe-js)

Distance Comparison Preserving Encryption (DCPE) for JavaScript. A framework that enables secure, end-to-end encryption of vector embeddings while preserving the ability to perform similarity search on the encrypted data.

## Features

- **Zero-Trust Security**: Client-side encryption and decryption via client-managed keys (BYOK)
- **Searchable Encryption**: Perform similarity search on encrypted vectors
- **Metadata Filtering**: Support for encrypted metadata fields with deterministic encryption
- **Vector Database Agnostic**: Works with any vector database through adapter interface
- **Next.js Compatible**: Designed for seamless integration with Next.js applications

## Installation

```bash
# Using npm
npm install dcpe-js

# Using yarn
yarn add dcpe-js

# Using pnpm
pnpm add dcpe-js
```

## Quick Start

```javascript
import { DCPE } from 'dcpe-js';

// Create a DCPE instance
const dcpe = new DCPE();

// Generate encryption keys
const keys = await dcpe.generateKeys();
dcpe.setKeys(keys);

// Encrypt a vector embedding
const vector = [0.1, 0.2, 0.3, 0.4];
const encryptedVector = dcpe.encryptVector(vector);

// Encrypt document text
const text = "This is a secret document.";
const encryptedText = dcpe.encryptText(text);

// Encrypt metadata for filtering
const category = "finance";
const encryptedCategory = dcpe.encryptMetadata(category);

// Store in your vector database
// { vector: encryptedVector, metadata: { text: encryptedText, category: encryptedCategory } }

// Later, decrypt the results
const decryptedText = dcpe.decryptText(encryptedText);
const decryptedCategory = dcpe.decryptMetadata(encryptedCategory);
```

## Working with Vector Databases

DCPE-JS can work with any vector database through its adapter interface:

```javascript
import { DCPE, BaseAdapter } from 'dcpe-js';

// Create a custom adapter for your vector database
class MyDatabaseAdapter extends BaseAdapter {
  constructor(config) {
    super(config);
    // Initialize your database client
  }

  async connect() {
    // Connect to your database
    return true;
  }

  async insert(vectors) {
    // Insert vectors into your database
    return ["id1", "id2"]; // Return inserted IDs
  }

  async search(queryVector, options) {
    // Search for similar vectors
    return [{ id: "id1", score: 0.95 }];
  }

  async disconnect() {
    // Clean up resources
  }
}

// Use your adapter
const adapter = new MyDatabaseAdapter({
  host: "https://your-db-host.com",
  apiKey: "your-api-key"
});

await adapter.connect();
```

## Next.js Integration

DCPE-JS is designed to work seamlessly with Next.js applications:

```javascript
// In your Next.js client component
'use client';
import { useState } from 'react';
import { DCPE } from 'dcpe-js';

export default function EncryptionComponent() {
  const [result, setResult] = useState('');
  
  const encryptData = async () => {
    // Create DCPE instance
    const dcpe = new DCPE();
    
    // Generate or load keys
    const keys = await dcpe.generateKeys();
    dcpe.setKeys(keys);
    
    // Encrypt data
    const vector = [0.1, 0.2, 0.3, 0.4];
    const encrypted = dcpe.encryptVector(vector);
    
    setResult(`Encrypted: ${JSON.stringify(encrypted)}`);
  };
  
  return (
    <div>
      <button onClick={encryptData}>Encrypt Data</button>
      <pre>{result}</pre>
    </div>
  );
}
```

## Advanced Configuration

DCPE-JS offers various configuration options:

```javascript
const dcpe = new DCPE({
  // Key provider configuration
  keyProvider: 'local', // 'local' is the default
  keyProviderConfig: {
    // Provider-specific options
  },
  
  // Vector configuration
  vectorConfig: {
    approximationFactor: 0.95 // Trade-off between security and performance
  }
});
```

## API Documentation

For detailed API documentation, see the API Reference.

## Examples

- Basic Vector Encryption
- Text and Metadata Encryption
- Next.js Integration
- Custom Database Adapter

## Advanced Usage

For more advanced usage scenarios, please refer to:
- Getting Started Guide
- Advanced Configuration
- Custom Adapter Implementation

## License

MIT License
```
