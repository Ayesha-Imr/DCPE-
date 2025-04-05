import { MilvusClient } from '@zilliz/milvus2-sdk-node';
import dotenv from 'dotenv';
import cohere from 'cohere-ai';
import puppeteer from 'puppeteer';

// Load environment variables
dotenv.config();

// Initialize Cohere client
cohere.apiKey = process.env.COHERE_API_KEY;

// Initialize Milvus client
const milvusClient = new MilvusClient({
  address: process.env.ZILLIZ_ENDPOINT,
  token: process.env.ZILLIZ_TOKEN,
});

const collectionName = 'Unencrypted_Data_March_2025';

// Function to extract content from a website URL
async function extractWebsiteContent(url) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
  
    try {
      await page.goto(url, { waitUntil: 'domcontentloaded' });
      const content = await page.evaluate(() => {
        return document.body.innerText;
      });
      console.log(content);
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

// Function to get query embedding using Cohere
async function getQueryEmbedding(query) {
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
  return data.embeddings[0];
}


// Function to perform vector search
async function vectorSearch(queryEmbedding) {
  const searchResults = await milvusClient.search({
    collection_name: collectionName,
    vectors: [queryEmbedding],
    search_params: {
      anns_field: 'vector',
      topk: 5,
      metric_type: 'COSINE',
      params: JSON.stringify({ nprobe: 10 }),
    },
    output_fields: ['chunk_text', 'source_url', 'upload_date'],
  });

  return searchResults.results; // Return raw search results
}


// Function to process data and prepare it for ingestion
async function processData(data, sourceUrl) {
    const processedData = [];
    const chunks = chunkText(data); // Use the chunkText function to split the data into chunks
  
    for (const chunkText of chunks) {
      const embedding = await getEmbeddings(chunkText); // Generate embeddings for each chunk
      const chunkDict = {
        source_url: sourceUrl,
        chunk_text: chunkText,
        upload_date: new Date().toISOString(), // Use current timestamp
        vector: embedding, // Add the embedding vector
      };
      processedData.push(chunkDict);
    }
  
    return processedData;
  }

// Function to process and ingest data
async function processAndIngestData(url) {
    // Extract text from the URL
    const textData = await extractWebsiteContent(url);
  
    // Process data
    const processedData = await processData(textData, url);
  
    // Insert data into Milvus collection
    await milvusClient.insert({
      collection_name: collectionName,
      fields_data: processedData,
    });
  
    return 'Data ingested successfully';
  }

  // Function to perform vector search and format results
async function searchQuery(query) {
    const queryEmbedding = await getQueryEmbedding(query); // Get query embedding
  
    const searchResults = await vectorSearch(queryEmbedding); // Perform vector search
  
    return searchResults;
  }


export { searchQuery, processAndIngestData, extractWebsiteContent, chunkText, getQueryEmbedding, vectorSearch, processData };