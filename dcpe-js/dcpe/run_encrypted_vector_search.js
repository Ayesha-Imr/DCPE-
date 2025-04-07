import dotenv from 'dotenv';
import { 
  initializeEncryptionClient,
  processAndIngestData, 
  searchQuery 
} from './encrypted_vector_search.js';

// Load environment variables
dotenv.config();

async function runTest() {
  try {
    console.log("=== Testing Encrypted Vector Search ===");
    
    // Step 1: Initialize encryption client
    console.log("Initializing encryption client...");
    await initializeEncryptionClient();
    
    // Step 2: Create collection if it doesn't exist
    // console.log("Creating encrypted collection...");
    // await createEncryptedCollection();
    
    // Step 3: Ingest sample data
    console.log("Ingesting encrypted sample data...");
    const testUrl = "https://dev.to/sattyam/claude-35-api-introductory-tutorial-m5o";
    await processAndIngestData(testUrl);
    
    // Wait a moment for ingestion to complete
    console.log("Waiting for data ingestion to settle...");
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    // Step 4: Perform a search query
    console.log("Performing encrypted search query...");
    const searchResults = await searchQuery("claude 3.5 api tutorial");
    
    // Step 5: Display results
    console.log("\n=== Search Results ===");
    searchResults.forEach((result, index) => {
      console.log(`\nResult ${index + 1} (Score: ${result.score}):`);
      console.log(`Source: ${result.source_url}`);
      console.log(`Date: ${result.upload_date}`);
      console.log(`Text: ${result.chunk_text.substring(0, 200)}...`);
    });
    
    console.log("\nTest completed successfully.");
    
  } catch (error) {
    console.error("Error during test:", error);
  }
}

// Run the test
runTest();