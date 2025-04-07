
```markdown
# Getting Started with DCPE-JS

This guide will walk you through the process of integrating DCPE-JS into your application to enable secure, searchable encryption for vector embeddings.

## Table of Contents

1. [Installation](#installation)
2. [Basic Setup](#basic-setup)
3. [Key Generation and Management](#key-generation-and-management)
4. [Encrypting Vectors](#encrypting-vectors)
5. [Encrypting Text Content](#encrypting-text-content)
6. [Working with Metadata](#working-with-metadata)
7. [Storing Encrypted Data](#storing-encrypted-data)
8. [Searching Encrypted Vectors](#searching-encrypted-vectors)
9. [Decrypting Results](#decrypting-results)
10. [Next.js Integration](#nextjs-integration)

## Installation

Install DCPE-JS using your preferred package manager:

```bash
# Using npm
npm install dcpe-js

# Using yarn
yarn add dcpe-js

# Using pnpm
pnpm add dcpe-js
```

## Basic Setup

First, import the DCPE class and create a new instance:

```javascript
import { DCPE } from 'dcpe-js';

// Create a DCPE instance with default configuration
const dcpe = new DCPE();
```

## Key Generation and Management

### Generating New Keys

To generate new encryption keys:

```javascript
// Generate encryption keys
const keys = await dcpe.generateKeys();

// Set the keys for the DCPE instance
dcpe.setKeys(keys);
```

### Saving and Loading Keys

It's important to securely store and manage your encryption keys:

```javascript
// Save keys securely
const saveKeys = (keys) => {
  // Store in secure storage (e.g., secure localStorage, secure cookie, HSM)
  localStorage.setItem('dcpe-keys', JSON.stringify(keys));
};

// Load keys
const loadKeys = () => {
  const storedKeys = localStorage.getItem('dcpe-keys');
  return storedKeys ? JSON.parse(storedKeys) : null;
};

// Usage
const keys = await dcpe.generateKeys();
saveKeys(keys);

// Later...
const loadedKeys = loadKeys();
if (loadedKeys) {
  dcpe.setKeys(loadedKeys);
}
```

> **Security Note**: In a production environment, you should store encryption keys in a secure manner, such as using a hardware security module (HSM), secure key vault, or other secure storage appropriate for your security requirements.

## Encrypting Vectors

To encrypt vector embeddings:

```javascript
// Original vector embedding (e.g., from an embedding model)
const vector = [0.1, 0.2, 0.3, 0.4, 0.5];

// Encrypt the vector
const encryptedVector = dcpe.encryptVector(vector);
```

The encrypted vectors preserve relative distances, allowing for similarity search while protecting the actual content.

## Encrypting Text Content

For encrypting document text or chunk content:

```javascript
// Original text
const text = "This is a confidential document that contains sensitive information.";

// Encrypt the text
const encryptedText = dcpe.encryptText(text);
// Returns { ciphertext, iv, tag } - all need to be stored
```

## Working with Metadata

For metadata fields that you want to filter on later:

```javascript
// Metadata values
const category = "finance";
const documentId = "doc-123456";

// Encrypt metadata using deterministic encryption (allows for exact match filtering)
const encryptedCategory = dcpe.encryptMetadata(category);
const encryptedDocumentId = dcpe.encryptMetadata(documentId);
```

## Storing Encrypted Data

When storing in a vector database, you'll typically combine encrypted vectors with encrypted metadata:

```javascript
// Structured document with encrypted components
const encryptedDocument = {
  vector: encryptedVector,
  metadata: {
    text: encryptedText,
    category: encryptedCategory,
    documentId: encryptedDocumentId
  }
};

// Store in your vector database using the appropriate adapter
// ...
```

## Searching Encrypted Vectors

To search for similar vectors:

```javascript
// Create a query vector and encrypt it
const queryVector = [0.15, 0.25, 0.35, 0.45, 0.55];
const encryptedQueryVector = dcpe.encryptVector(queryVector);

// Optional filter with encrypted metadata
const filter = {
  category: dcpe.encryptMetadata("finance")
};

// Search using your database adapter
const results = await databaseAdapter.search(encryptedQueryVector, {
  limit: 10,
  filter: filter
});
```

## Decrypting Results

After retrieving results, decrypt the data:

```javascript
// Process search results
const processedResults = results.map(result => {
  return {
    id: result.id,
    score: result.score,
    // Decrypt the text and metadata
    text: dcpe.decryptText(result.metadata.text),
    category: dcpe.decryptMetadata(result.metadata.category),
    documentId: dcpe.decryptMetadata(result.metadata.documentId)
  };
});
```

## Next.js Integration

DCPE-JS can be used in Next.js applications in both client and server components:

### Client Component Example

```javascript
'use client';
import { useState, useEffect } from 'react';
import { DCPE } from 'dcpe-js';

export default function SearchComponent() {
  const [dcpe, setDcpe] = useState(null);
  const [results, setResults] = useState([]);
  const [query, setQuery] = useState('');
  
  // Initialize DCPE
  useEffect(() => {
    const initDcpe = async () => {
      const instance = new DCPE();
      // In a real app, you would load keys from secure storage
      const keys = await instance.generateKeys();
      instance.setKeys(keys);
      setDcpe(instance);
    };
    
    initDcpe();
  }, []);
  
  const handleSearch = async () => {
    if (!dcpe || !query) return;
    
    // In a real app, you would:
    // 1. Get embeddings for the query text
    const mockQueryVector = [0.1, 0.2, 0.3, 0.4];
    
    // 2. Encrypt the query vector
    const encryptedQueryVector = dcpe.encryptVector(mockQueryVector);
    
    // 3. Search the database (mock for this example)
    const mockResults = [
      {
        id: 'doc1',
        score: 0.95,
        metadata: {
          text: { /* encrypted text object */ },
          category: /* encrypted category buffer */
        }
      }
    ];
    
    // 4. Decrypt the results
    const decryptedResults = mockResults.map(result => ({
      id: result.id,
      score: result.score,
      // In a real app, you would decrypt actual encrypted data
      text: "This is the decrypted text",
      category: "finance"
    }));
    
    setResults(decryptedResults);
  };
  
  return (
    <div>
      <input 
        value={query} 
        onChange={(e) => setQuery(e.target.value)} 
        placeholder="Search..." 
      />
      <button onClick={handleSearch}>Search</button>
      <ul>
        {results.map(result => (
          <li key={result.id}>
            <strong>{result.category}</strong>: {result.text} (Score: {result.score})
          </li>
        ))}
      </ul>
    </div>
  );
}
```


