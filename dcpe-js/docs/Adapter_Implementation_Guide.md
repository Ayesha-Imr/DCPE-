# DCPE-JS

Distance Comparison Preserving Encryption for JavaScript. Enables secure, end-to-end encryption of vector embeddings while preserving the ability to perform vector search on the encrypted data.

## Basic Usage

```javascript
import { DCPE } from 'dcpe-js';

// Create a DCPE instance
const dcpe = new DCPE();

// Generate encryption keys
const keys = await dcpe.generateKeys();
dcpe.setKeys(keys);

// Encrypt a vector
const vector = [0.1, 0.2, 0.3, 0.4];
const encryptedVector = dcpe.encryptVector(vector);

// Encrypt text (e.g., chunk content)
const text = "This is a secret message.";
const encryptedText = dcpe.encryptText(text);

// Encrypt metadata for filtering
const metadata = "category:finance";
const encryptedMetadata = dcpe.encryptMetadata(metadata);
    
```

## Implementing a Custom Database Adapter
To integrate with your preferred vector database, create a custom adapter by extending the BaseAdapter class:

```javascript
import { BaseAdapter } from 'dcpe-js';

class CustomVectorDBAdapter extends BaseAdapter {
  constructor(config) {
    super(config);
    // Initialize your database client
    this.client = null;
  }

  async connect() {
    // Connect to your database
    this.client = await createYourDatabaseClient(this.config);
    return true;
  }

  async disconnect() {
    // Disconnect from your database
    if (this.client) {
      await this.client.close();
      this.client = null;
    }
  }

  async insert(vectors) {
    // Insert vectors into your database
    // Each vector should have at least: { id, vector, metadata }
    return await this.client.insert(vectors);
  }

  async search(queryVector, options) {
    // Search for similar vectors
    // Return results in format: [{ id, distance, metadata }]
    return await this.client.search(queryVector, options);
  }
}
    
``` 

## Next.js Integration
For Next.js applications, you can use DCPE-JS in both client and server components:

```javascript
// For client-side components
'use client';
import { DCPE } from 'dcpe-js';

export default function ClientComponent() {
  const encryptData = () => {
    const dcpe = new DCPE();
    // ... encryption logic
  };
  
  return <button onClick={encryptData}>Encrypt</button>;
}
    
```