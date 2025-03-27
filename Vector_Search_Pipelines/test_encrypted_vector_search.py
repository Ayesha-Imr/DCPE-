import os
import time
import base64
import json
from dotenv import load_dotenv

from DCPE.rag_encryption_module import RagEncryptionClient
from Vector_Search_Pipelines.encrypted_vector_search import search_query, search_with_metadata_filter, process_and_ingest_data

# Load environment variables
load_dotenv(override=True)

KEY_FILE = "encryption_key.json"

# Initialize the encryption client
RAW_ENCRYPTION_KEY = RagEncryptionClient.get_or_create_encryption_key(KEY_FILE)
APPROXIMATION_FACTOR = 1.5
rag_client = RagEncryptionClient(
    encryption_key=RAW_ENCRYPTION_KEY,
    approximation_factor=APPROXIMATION_FACTOR
)

# Test URLs to ingest (very random - found short articles I could use, don't judge)
TEST_URLS = [
    "https://dev.to/foxgem/vibe-coding-an-exploration-of-ai-assisted-development-2dkm",  # Vibe coding article
    "https://dev.to/tiarman/javascript-overview-102d",  # JavaScript article
    "https://dev.to/alexroor4/ai-agents-vs-chatbots-whats-the-difference-and-which-one-do-you-need-46fi"  # AI article
]

# Test queries
QUERIES = {
    "vibe_coding": "What is vibe coding and how does it impact software development?",
    "javascript": "Explain JavaScript objects and their properties",
    "ai_tools": "How can AI tools help software engineering teams?"
}

def run_test(test_name, query, filter_options=None, expected_urls=None):
    """Run a single test and display results."""
    print(f"\n{'=' * 80}\nTEST: {test_name}\n{'=' * 80}")
    print(f"Query: {query}")
    
    if filter_options:
        print(f"Filter options: {json.dumps(filter_options, indent=2)}")
        results = search_with_metadata_filter(query, filter_options, rag_client)
    else:
        print("No filters applied (basic search)")
        results = search_query(query, rag_client)
    
    print("\nRESULTS:")
    print(results)
    
    # Simple validation if expected URLs are provided
    if expected_urls:
        expected_found = all(url in results for url in expected_urls)
        print(f"\nExpected URLs found: {'✅ Yes' if expected_found else '❌ No'}")
    
    print(f"\n{'=' * 80}\n")
    return results

def test_basic_search():
    """Test basic vector search without any filters."""
    return run_test(
        "Basic Vector Search (No Filters)",
        QUERIES["vibe_coding"],
        expected_urls=[TEST_URLS[0]]
    )

def test_equality_filter():
    """Test search with equality filter on source URL."""
    filter_options = {
        "filters": [
            {"field": "source_url", "op": "==", "value": TEST_URLS[0]}
        ]
    }
    return run_test(
        "Equality Filter (source_url == TEST_URLS[0])",
        QUERIES["vibe_coding"],
        filter_options,
        expected_urls=[TEST_URLS[0]]
    )

def test_date_equality_filter():
    """Test search with equality filter on upload date."""
    current_date = time.strftime("%Y-%m-%d")
    filter_options = {
        "filters": [
            {"field": "upload_date", "op": "==", "value": current_date}
        ]
    }
    return run_test(
        "Date Equality Filter (upload_date == today)",
        QUERIES["vibe_coding"],
        filter_options
    )

def test_multiple_conditions_and():
    """Test search with multiple conditions combined with AND."""
    current_date = time.strftime("%Y-%m-%d")
    filter_options = {
        "filters": [
            {"field": "source_url", "op": "==", "value": TEST_URLS[0]},
            {"field": "upload_date", "op": "==", "value": current_date}
        ],
        "logic": "AND"
    }
    return run_test(
        "Multiple Conditions with AND",
        QUERIES["vibe_coding"],
        filter_options,
        expected_urls=[TEST_URLS[0]]
    )

def test_multiple_conditions_or():
    """Test search with multiple conditions combined with OR."""
    filter_options = {
        "filters": [
            {"field": "source_url", "op": "==", "value": TEST_URLS[0]},
            {"field": "source_url", "op": "==", "value": TEST_URLS[1]}
        ],
        "logic": "OR"
    }
    return run_test(
        "Multiple Conditions with OR",
        QUERIES["vibe_coding"],
        filter_options,
        expected_urls=[TEST_URLS[0]]
    )

def test_in_operator():
    """Test search with IN operator for multiple possible values."""
    filter_options = {
        "filters": [
            {"field": "source_url", "op": "IN", "value": [
                TEST_URLS[0],
                TEST_URLS[1]
            ]}
        ]
    }
    return run_test(
        "IN Operator (source_url IN [URL1, URL2])",
        QUERIES["vibe_coding"],
        filter_options,
        expected_urls=[TEST_URLS[0]]
    )

def test_template_expression():
    """Test search with template expression for filtering."""
    current_date = time.strftime("%Y-%m-%d")
    filter_options = {
        "expr": "source_url == {url} AND upload_date == {date}",
        "params": {
            "url": TEST_URLS[0],
            "date": current_date
        }
    }
    return run_test(
        "Template Expression (source_url == URL AND upload_date == date)",
        QUERIES["vibe_coding"],
        filter_options,
        expected_urls=[TEST_URLS[0]]
    )

def test_multiple_url_template():
    """Test search with IN template for multiple URLs."""
    filter_options = {
        "expr": "source_url IN {urls}",
        "params": {
            "urls": [TEST_URLS[0], TEST_URLS[1]]
        }
    }
    return run_test(
        "Template with IN Operator for Multiple URLs",
        QUERIES["vibe_coding"],
        filter_options,
        expected_urls=[TEST_URLS[0]]
    )

def ingest_test_data():
    """Ingest test data for all test URLs."""
    print("\n--- Ingesting Test Data ---")
    for url in TEST_URLS:
        print(f"Ingesting: {url}")
        try:
            result = process_and_ingest_data(url, rag_client)
            print(f"Ingested {len(result)} chunks")
        except Exception as e:
            print(f"Error ingesting {url}: {str(e)}")
    print("--- Ingestion Complete ---\n")

def main():
    # Step 1: Ingest test data
    ingest_test_data()
    
    # Step 2: Wait a moment for data to be indexed
    print("Waiting for data indexing...")
    time.sleep(5)
    
    # Step 3: Run the tests
    print("\n--- Starting Search Tests ---\n")
    
    # Basic search test
    test_basic_search()
    
    # Filtering tests
    test_equality_filter()
    test_date_equality_filter()
    test_multiple_conditions_and()
    test_multiple_conditions_or()
    test_in_operator()
    test_template_expression()
    test_multiple_url_template()
    
    print("\n--- All Tests Completed ---")

if __name__ == "__main__":
    main()