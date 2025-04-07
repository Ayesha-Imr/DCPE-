# Advanced Configuration for DCPE-JS

This guide covers advanced configuration options and customization for the DCPE-JS library.

## Table of Contents

1. [DCPE Configuration Options](#dcpe-configuration-options)
2. [Key Provider Customization](#key-provider-customization)
3. [Performance Tuning](#performance-tuning)
4. [Security Considerations](#security-considerations)
5. [Vector Database Adapter Configuration](#vector-database-adapter-configuration)
6. [Environment-Specific Settings](#environment-specific-settings)

## DCPE Configuration Options

When creating a new DCPE instance, you can provide various configuration options:

```javascript
const dcpe = new DCPE({
  // Key provider configuration
  keyProvider: 'local',          // Default: 'local'
  keyProviderConfig: {           // Provider-specific options
    // Options specific to the key provider
  },
  
  // Vector configuration
  vectorConfig: {
    approximationFactor: 0.95    // Trade-off between security and performance (default: 1.0)
  }
});
```

### Available Key Providers

DCPE-JS supports the following key providers:

- `'local'`: Stores keys in memory (default)
- `'client'`: Uses a client-side key store (e.g., Zustand)

### Vector Configuration Options

- `approximationFactor`: Controls the trade-off between security and performance
  - Range: 0.0 - 1.0
  - Default: 1.0 (highest security)
  - Lower values improve performance but may slightly reduce security

## Key Provider Customization

### Creating a Custom Key Provider

You can create custom key providers by extending the `KeyProvider` class:

```javascript
import { keyProvider } from 'dcpe-js';

class CustomKeyProvider extends keyProvider.KeyProvider {
  constructor(config) {
    super();
    this.config = config;
    this.keyStore = new SecureKeyStore(config); // Your secure key storage
  }
  
  async getKey(keyId) {
    // Implement secure key retrieval
    const key = await this.keyStore.getKey(keyId || 'default');
    if (!key) throw new Error(`Key not found: ${keyId}`);
    return Buffer.from(key, 'base64');
  }
  
  async storeKey(keyMaterial, keyId) {
    // Implement secure key storage
    const actualKeyId = keyId || 'default';
    await this.keyStore.storeKey(actualKeyId, keyMaterial.toString('base64'));
    return actualKeyId;
  }
  
  setKeys(encryptionKeys) {
    // Implement key setting
    if (Buffer.isBuffer(encryptionKeys)) {
      this.currentKey = encryptionKeys;
    } else {
      this.currentKey = encryptionKeys.key || encryptionKeys;
    }
  }
  
  getKeys() {
    // Return current keys
    if (!this.currentKey) throw new Error("No keys have been set");
    return this.currentKey;
  }
}

// Usage
const dcpe = new DCPE({
  keyProvider: 'custom',
  keyProviderConfig: {
    // Your custom key provider config
    secureStorage: 'my-secure-storage'
  }
});

// Register custom key provider
dcpe._keyProviders = {
  ...dcpe._keyProviders,
  custom: (config) => new CustomKeyProvider(config)
};
```

### Integrating with External Key Management Systems

For integrating with Key Management Systems (KMS) or Hardware Security Modules (HSM):

```javascript
class KmsKeyProvider extends keyProvider.KeyProvider {
  constructor(config) {
    super();
    this.kmsClient = new KmsClient(config.region);
    this.keyId = config.keyId;
  }
  
  async getKey(keyId) {
    // Retrieve key material from KMS
    const response = await this.kmsClient.decrypt({
      KeyId: this.keyId,
      CiphertextBlob: Buffer.from(keyId, 'base64')
    });
    return response.Plaintext;
  }
  
  // Implement other required methods
}
```

## Performance Tuning

### Approximation Factor

The `approximationFactor` parameter controls the trade-off between security and performance:

```javascript
// Higher security but potentially slower
const dcpeHighSecurity = new DCPE({
  vectorConfig: { approximationFactor: 1.5 }
});

// Balanced approach
const dcpeBalanced = new DCPE({
  vectorConfig: { approximationFactor: 1.2 }
});

// Optimized for performance
const dcpePerformance = new DCPE({
  vectorConfig: { approximationFactor: 1.0 }
});
```

### Caching Strategies

For improved performance, consider implementing caching for frequently used encrypted values:

```javascript
// Simple cache implementation
const encryptionCache = new Map();

// Cached encryption
const encryptWithCache = (dcpe, value, cacheKey) => {
  if (encryptionCache.has(cacheKey)) {
    return encryptionCache.get(cacheKey);
  }
  
  const encrypted = dcpe.encryptMetadata(value);
  encryptionCache.set(cacheKey, encrypted);
  return encrypted;
};

// Usage
const encryptedCategory = encryptWithCache(dcpe, 'finance', 'category:finance');
```

## Security Considerations

### Key Rotation

Implementing regular key rotation improves security:

```javascript
// Key rotation function
const rotateKeys = async (dcpe) => {
  // Generate new keys
  const newKeys = await dcpe.generateKeys();
  
  // Re-encrypt data with new keys (pseudo-code)
  const documents = await fetchAllDocuments();
  
  for (const doc of documents) {
    // Decrypt with old keys
    const vector = dcpe.decryptVector(doc.vector);
    const text = dcpe.decryptText(doc.metadata.text);
    
    // Set new keys
    dcpe.setKeys(newKeys);
    
    // Re-encrypt with new keys
    const newEncryptedVector = dcpe.encryptVector(vector);
    const newEncryptedText = dcpe.encryptText(text);
    
    // Update in database
    await updateDocument(doc.id, {
      vector: newEncryptedVector,
      metadata: { text: newEncryptedText }
    });
  }
  
  // Save new keys securely
  saveKeysSecurely(newKeys);
};
```

### Secure Key Storage

Always store encryption keys securely:

- In browser environments, consider using the Web Crypto API's `subtle.importKey` and `subtle.exportKey`
- For Node.js applications, consider secure environment variables or a dedicated key management service

## Vector Database Adapter Configuration

### Configuring Vector Database Adapters

Each vector database adapter can be configured with database-specific options:

```javascript
import { BaseAdapter } from 'dcpe-js';

class WeaviateAdapter extends BaseAdapter {
    constructor(config) {
        super({
            host: config.host,
            apiKey: config.apiKey,
            className: config.className,
            dimension: config.dimension || 1536,
            metricType: config.metricType || 'cosine',
            ...config
        });
        
        // Additional adapter-specific configuration
        this.scheme = config.scheme || 'https';
        this.tenantId = config.tenantId;
    }
    
    // Implementation of required methods
}
```


### Optimizing Search Parameters

Fine-tuning search parameters for your specific use case:

```javascript
// Basic search
const basicResults = await adapter.search(encryptedVector, {
  limit: 10
});

// Advanced search with filters
const advancedResults = await adapter.search(encryptedVector, {
  limit: 20,
  threshold: 0.8, // Similarity threshold
  filter: {
    category: encryptedCategory,
    date: { $gt: encryptedDate }
  },
  includeVectors: false, // Don't return vectors to save bandwidth
  includeMetadata: true  // Include metadata in results
});
```

## Environment-Specific Settings

### Next.js Environment Configuration

For Next.js applications, consider environment-specific configurations:

```javascript
// In your Next.js app
const initDcpe = () => {
  return new DCPE({
    keyProvider: process.env.NEXT_PUBLIC_KEY_PROVIDER || 'local',
    vectorConfig: {
      approximationFactor: parseFloat(process.env.NEXT_PUBLIC_APPROXIMATION_FACTOR || '0.95')
    }
  });
};
```

### Server vs. Client Side Usage

For Next.js, be mindful of server vs. client components:

```javascript
// For client components
'use client';
import { DCPE } from 'dcpe-js';

export function ClientSideDcpe() {
  // Full client-side implementation
}

// For server components with client hooks
import { DCPE } from 'dcpe-js';

export async function ServerComponent() {
  // Server-side operations
  // Note: Key operations should generally be client-side
  return (
    <ClientWrapper />
  );
}
```

For more specific use cases or advanced configurations, refer to the API Reference or [contact our support team](mailto:ayesha.ml2002@gmail.com).
