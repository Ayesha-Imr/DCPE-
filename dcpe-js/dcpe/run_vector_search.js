import { processAndIngestData, searchQuery } from './vector_search.js';

async function main() {
  try {
    // Step 1: Process and ingest data from a URL
    // const url = 'https://dev.to/syed_mudasseranayat_e251/understanding-generative-ai-the-future-of-creativity-4m58'; 
    // console.log(`Processing and ingesting data from: ${url}`);
    // const ingestResult = await processAndIngestData(url);
    // console.log(ingestResult);

    // Step 2: Perform vector search with a query
    const query = 'Generative AI and its impact on creativity'; 
    console.log(`Performing vector search for query: "${query}"`);
    const searchResults = await searchQuery(query);
    console.log('Search Results:', searchResults);
  } catch (error) {
    console.error('Error:', error);
  }
}

main();