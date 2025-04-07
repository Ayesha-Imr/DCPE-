import { MilvusClient } from '@zilliz/milvus2-sdk-node';
import dotenv from 'dotenv';
import cohere from 'cohere-ai';
import puppeteer from 'puppeteer';
import { RagEncryptionClient } from '../rag_encryption/index.js';

// Load environment variables
dotenv.config();

// Initialize Cohere client
cohere.apiKey = process.env.COHERE_API_KEY;

// Initialize Milvus client
const milvusClient = new MilvusClient({
  address: process.env.ZILLIZ_ENDPOINT,
  token: process.env.ZILLIZ_TOKEN,
});

const collectionName = 'Encrypted_Data_March_2025';

// Initialize DCPE client
let encryptionClient = null;

/**
 * Initialize the encryption client with the provided key or from environment variables
 */
async function initializeEncryptionClient(encryptionKey = null) {
  // If a key is provided directly, use it; otherwise, use environment variable
  const key = encryptionKey || Buffer.from(process.env.DCPE_ENCRYPTION_KEY, 'hex');
  
  // Approximation factor for vector encryption
  const approximationFactor = parseFloat(process.env.DCPE_APPROXIMATION_FACTOR || '1.0');
  
  // Initialize the client
  encryptionClient = await RagEncryptionClient.create(key, approximationFactor);
  return encryptionClient;
}

// Function to extract content from a website URL
async function extractWebsiteContent(url) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();

  try {
    await page.goto(url, { waitUntil: 'domcontentloaded' });
    const content = await page.evaluate(() => {
      return document.body.innerText;
    });
    return content;
  } catch (error) {
    console.error('Error extracting website content:', error);
    throw error;
  } finally {
    await browser.close();
  }
}

// Function to chunk text into smaller pieces
function chunkText(text, chunkSize = 600, chunkOverlap = 20) {
  const chunks = [];
  let start = 0;

  while (start < text.length) {
    const end = Math.min(start + chunkSize, text.length);
    const chunk = text.slice(start, end);
    chunks.push(chunk);

    // Move the start index forward by chunkSize minus overlap
    start += chunkSize - chunkOverlap;
  }

  return chunks;
}

// Function to get embeddings using Cohere
async function getEmbeddings(text) {
  const response = await fetch('https://api.cohere.ai/embed', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${process.env.COHERE_API_KEY}`,
    },
    body: JSON.stringify({
      model: 'embed-english-light-v3.0',
      texts: [text],
      truncate: 'RIGHT',
      input_type: 'search_document',
    }),
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch embeddings: ${response.statusText}`);
  }

  const data = await response.json();
  return data.embeddings[0];
}

// Function to get query embedding and encrypt it
async function getQueryEmbedding(query) {
  // Make sure encryption client is initialized
  if (!encryptionClient) {
    await initializeEncryptionClient();
  }
  
  // Get original embedding
  const response = await fetch('https://api.cohere.ai/embed', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${process.env.COHERE_API_KEY}`,
    },
    body: JSON.stringify({
      model: 'embed-english-light-v3.0',
      texts: [query],
      truncate: 'RIGHT',
      input_type: 'search_query',
    }),
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch query embedding: ${response.statusText}`);
  }

  const data = await response.json();
  const embedding = data.embeddings[0];
  
  // Encrypt the query vector - we don't actually store this metadata
  // but return it for decryption later
  const [encryptedVector, vectorMetadata] = encryptionClient.encryptVector(embedding);
  
  return { 
    encryptedVector, 
    vectorMetadata 
  };
}

// Function to perform vector search with encrypted vectors
async function vectorSearch(encryptedQueryEmbedding) {
  const searchResults = await milvusClient.search({
    collection_name: collectionName,
    vectors: [encryptedQueryEmbedding],
    search_params: {
      anns_field: 'vector',
      topk: 5,
      metric_type: 'COSINE',
      params: JSON.stringify({ nprobe: 10 }),
    },
    output_fields: ['chunk_text', 'source_url', 'upload_date'],
  });

  
  // Debug the full response structure # CONSOLE LOG ADDED
  console.log("Full search response structure:", JSON.stringify(searchResults, null, 2));

  return searchResults.results; // Return raw search results
}

async function filteredVectorSearch(encryptedQueryEmbedding, filterOptions = {}) {
  try {
    // Build filter expression based on provided options
    let filterExpr = '';
    
    // Filter by source URL (deterministic encryption)
    if (filterOptions.sourceUrl) {
      // Encrypt the URL using deterministic encryption to match stored values
      if (!encryptionClient) {
        await initializeEncryptionClient();
      }
      
      // Convert URL to the same format as stored in the database 
      const encryptedUrl = encryptionClient
        .encryptDeterministicText(filterOptions.sourceUrl)
        .toString('base64');
        
      filterExpr = `source_url == "${encryptedUrl}"`;
    }
    
    // Filter by date range
    if (filterOptions.startDate && filterOptions.endDate) {
      const dateFilter = `(upload_date >= "${filterOptions.startDate}" and upload_date <= "${filterOptions.endDate}")`;
      filterExpr = filterExpr ? `${filterExpr} and ${dateFilter}` : dateFilter;
    } else if (filterOptions.startDate) {
      const dateFilter = `upload_date >= "${filterOptions.startDate}"`;
      filterExpr = filterExpr ? `${filterExpr} and ${dateFilter}` : dateFilter;
    } else if (filterOptions.endDate) {
      const dateFilter = `upload_date <= "${filterOptions.endDate}"`;
      filterExpr = filterExpr ? `${filterExpr} and ${dateFilter}` : dateFilter;
    }
    
    // Additional custom filter expression
    if (filterOptions.customFilter) {
      filterExpr = filterExpr 
        ? `${filterExpr} and (${filterOptions.customFilter})` 
        : filterOptions.customFilter;
    }
    
    // Prepare search options
    const searchOptions = {
      collection_name: collectionName,
      vectors: [encryptedQueryEmbedding],
      search_params: {
        anns_field: 'vector',
        topk: filterOptions.limit || 5,
        metric_type: 'COSINE',
        params: JSON.stringify({ nprobe: filterOptions.nprobe || 10 }),
      },
      output_fields: ['chunk_text', 'source_url', 'upload_date'],
    };
    
    // Add filter if we have one
    if (filterExpr) {
      searchOptions.filter = filterExpr;
      console.log(`Applying filter: ${filterExpr}`);
    }

    const searchResults = await milvusClient.search(searchOptions);
    
    // Debug the full response structure with applied filters
    console.log("Filtered search response:", JSON.stringify(searchResults, null, 2));

    return searchResults.results; 
  } catch (error) {
    console.error("Error in filtered vector search:", error);
    throw error;
  }
}

// Function to process data and prepare it for ingestion with encryption
async function processData(data, sourceUrl) {
  // Make sure encryption client is initialized
  if (!encryptionClient) {
    await initializeEncryptionClient();
  }
  
  const processedData = [];
  const chunks = chunkText(data);

  for (const chunkText of chunks) {
    // Generate embeddings for each chunk
    const embedding = await getEmbeddings(chunkText);
    
    // Encrypt the vector embedding
    const [encryptedVector, vectorMetadata] = encryptionClient.encryptVector(embedding);
    
    // Encrypt the chunk text using standard encryption
    const encryptedText = encryptionClient.encryptText(chunkText);
    
    // Encrypt the source URL using deterministic encryption (for filtering)
    const encryptedUrl = encryptionClient.encryptDeterministicText(sourceUrl);
    
    // Properly serialize buffers to base64 strings for VARCHAR storage
    const chunkDict = {
      source_url: encryptedUrl.toString('base64'),
      chunk_text: Buffer.concat([encryptedText.iv, encryptedText.ciphertext, encryptedText.tag]).toString('base64'),
      upload_date: new Date().toISOString(), // Not encrypted as it's just a timestamp
      vector: encryptedVector,
    };
    
    processedData.push(chunkDict);
  }

  return processedData;
}

// Function to process and ingest data with encryption
async function processAndIngestData(url) {
  // Extract text from the URL
  const textData = await extractWebsiteContent(url);

  // Process data with encryption
  const processedData = await processData(textData, url);

  // Insert data into Milvus collection
  await milvusClient.insert({
    collection_name: collectionName,
    fields_data: processedData,
  });

  return 'Encrypted data ingested successfully';
}

// Function to perform vector search and format results with decryption
async function searchQuery(query, filterOptions = {}) {
  // Make sure encryption client is initialized
  if (!encryptionClient) {
    await initializeEncryptionClient();
  }
  
  // Get and encrypt query embedding
  const { encryptedVector, vectorMetadata } = await getQueryEmbedding(query);

  // Perform vector search with or without filters
  const searchResults = filterOptions && Object.keys(filterOptions).length > 0
    ? await filteredVectorSearch(encryptedVector, filterOptions)
    : await vectorSearch(encryptedVector);
  
  // Add debugging to check search results structure
  console.log("Search results structure:", JSON.stringify(searchResults[0], null, 2));
    
  // Decrypt search results with proper error handling
  const decryptedResults = searchResults.map(result => {
    try {
      // Skip processing "[object Object]" results from previous incorrect storage
      if (result.chunk_text === "[object Object]" || !result.chunk_text) {
        console.warn("Found incorrectly serialized data:", result.chunk_text);
        return {
          error: "Incorrectly stored encrypted data",
          score: result.score,
          raw_result: result
        };
      }
      
      // Convert base64 string to Buffer
      const encryptedChunkBuffer = Buffer.from(result.chunk_text, 'base64');
      
      // Extract components from the encrypted chunk text
      const iv = encryptedChunkBuffer.subarray(0, 12);
      const tag = encryptedChunkBuffer.subarray(encryptedChunkBuffer.length - 16);
      const ciphertext = encryptedChunkBuffer.subarray(12, encryptedChunkBuffer.length - 16);
      
      // Decrypt the chunk text
      const decryptedText = encryptionClient.decryptText(ciphertext, iv, tag);
      
      // Handle source_url similarly
      let decryptedUrl = result.source_url;
      
      // Skip processing "[object Object]" urls from previous incorrect storage
      if (result.source_url !== "[object Object]") {
        try {
          const encryptedSourceBuffer = Buffer.from(result.source_url, 'base64');
          decryptedUrl = encryptionClient.decryptDeterministicText(encryptedSourceBuffer);
        } catch (urlError) {
          console.warn("Could not decrypt URL:", urlError.message);
        }
      }
      
      // Return decrypted result
      return {
        source_url: decryptedUrl,
        chunk_text: decryptedText,
        score: result.score,
        upload_date: result.upload_date,
      };
    } catch (error) {
      console.error("Error decrypting result:", error);
      return {
        error: `Decryption failed: ${error.message}`,
        score: result.score
      };
    }
  });
  
  // Filter out results with errors
  return decryptedResults.filter(result => !result.error);
}

// Function to create the encrypted collection
// async function createEncryptedCollection() {
//   try {
//     // Check if collection already exists
//     const hasCollection = await milvusClient.hasCollection({
//       collection_name: collectionName,
//     });

//     if (hasCollection.value) {
//       console.log(`Collection ${collectionName} already exists.`);
//       return;
//     }

//     // Create collection with appropriate schema
//     await milvusClient.createCollection({
//       collection_name: collectionName,
//       fields: [
//         {
//           name: 'id',
//           description: 'ID field',
//           data_type: 5, // DataType.Int64
//           is_primary_key: true,
//           autoID: true,
//         },
//         {
//           name: 'encrypted_source_url',
//           description: 'Deterministically encrypted URL',
//           data_type: 21, // DataType.BINARY_VECTOR
//           type_params: {
//             max_length: '1024', // Adjust based on your encrypted URL size
//           },
//         },
//         {
//           name: 'encrypted_chunk_text',
//           description: 'Encrypted text chunk',
//           data_type: 21, // DataType.BINARY_VECTOR
//           type_params: {
//             max_length: '10240', // Adjust based on your expected chunk size
//           },
//         },
//         {
//           name: 'upload_date',
//           description: 'Upload timestamp',
//           data_type: 20, // DataType.VARCHAR
//           type_params: {
//             max_length: '64',
//           },
//         },
//         {
//           name: 'vector',
//           description: 'Encrypted vector embedding',
//           data_type: 6, // DataType.FloatVector
//           type_params: {
//             dim: '1024', // Must match your cohere embedding dimension
//           },
//         },
//         {
//           name: 'vector_metadata',
//           description: 'Vector encryption metadata',
//           data_type: 21, // DataType.BINARY_VECTOR
//           type_params: {
//             max_length: '256', // Adjust based on your metadata size
//           },
//         },
//       ],
//       enable_dynamic_field: true,
//     });

//     // Create index
//     await milvusClient.createIndex({
//       collection_name: collectionName,
//       field_name: 'vector',
//       index_type: 'FLAT',
//       metric_type: 'COSINE',
//     });

//     // Load collection to memory
//     await milvusClient.loadCollection({
//       collection_name: collectionName,
//     });

//     console.log(`Collection ${collectionName} created successfully.`);
//   } catch (error) {
//     console.error('Error creating collection:', error);
//     throw error;
//   }
// }

export { 
  searchQuery, 
  processAndIngestData, 
  extractWebsiteContent, 
  chunkText, 
  getQueryEmbedding, 
  vectorSearch, 
  filteredVectorSearch,
  processData,
  // createEncryptedCollection, 
  initializeEncryptionClient 
};