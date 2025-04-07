import dotenv from 'dotenv';
import { 
    filteredVectorSearch,
  initializeEncryptionClient,
  processAndIngestData, 
  searchQuery 
} from './encrypted_vector_search.js';

// Load environment variables
dotenv.config();

async function testNormalSearch() {
  try {
    console.log("=== Testing Encrypted Vector Search ===");
    
    // Step 1: Initialize encryption client
    console.log("Initializing encryption client...");
    await initializeEncryptionClient();
    
    // Step 2: Create collection if it doesn't exist
    // console.log("Creating encrypted collection...");
    // await createEncryptedCollection();
    
    // Step 3: Ingest sample data
    // console.log("Ingesting encrypted sample data...");
    // const testUrl = "https://dev.to/vijaykodam/claude-code-agentic-code-demo-1n1c";
    // await processAndIngestData(testUrl);
    
    // // Wait a moment for ingestion to complete
    // console.log("Waiting for data ingestion to settle...");
    // await new Promise(resolve => setTimeout(resolve, 3000));
    
    // Step 4: Perform a search query
    console.log("Performing encrypted search query...");
    const searchResults = await searchQuery("claude agentic");

    
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

async function testFilteredSearch() {
    try {
      console.log("=== Testing Filtered Encrypted Vector Search ===");
      
      // Step 1: Initialize encryption client
      console.log("Initializing encryption client...");
      await initializeEncryptionClient();
      
      // Step 2: Perform a search query with a URL filter
      console.log("Performing filtered encrypted search query...");
      
      // Example filter options - searching for a specific source
      const filterOptions = {
        sourceUrl: "https://dev.to/sattyam/claude-35-api-introductory-tutorial-m5o",
        // You can also use date filters
        // startDate: "2025-04-01T00:00:00.000Z",
        // endDate: "2025-04-08T00:00:00.000Z"
      };
      
      const searchResults = await searchQuery(
        "claude agentic", 
        filterOptions
      );
      
      // Step 3: Display results
      console.log("\n=== Filtered Search Results ===");
      if (searchResults.length > 0) {
        searchResults.forEach((result, index) => {
          console.log(`\nResult ${index + 1} (Score: ${result.score}):`);
          console.log(`Source: ${result.source_url}`);
          console.log(`Date: ${result.upload_date}`);
          console.log(`Text: ${result.chunk_text.substring(0, 200)}...`);
        });
      } else {
        console.log("No results found matching the filter criteria.");
      }
      
      console.log("\nFiltered search test completed successfully.");
      
    } catch (error) {
      console.error("Error during filtered search test:", error);
    }
  }

// Run the test
testFilteredSearch();