import os
import time
import json
import base64
import numpy as np
from dotenv import load_dotenv
from pymilvus import MilvusClient, connections, Collection
from langchain_text_splitters import RecursiveCharacterTextSplitter
import cohere
from docling.document_converter import DocumentConverter

# Fix import path - Using absolute import to access the DCPE module
from DCPE.rag_encryption_module import RagEncryptionClient

# Load environment variables
load_dotenv(override=True)  # Force override existing environment variables

# Load API keys and endpoints
COHERE_API_KEY = os.getenv('COHERE_API_KEY')
ZILLIZ_ENDPOINT = os.getenv('ZILLIZ_ENDPOINT')
ZILLIZ_TOKEN = os.getenv('ZILLIZ_TOKEN')

KEY_FILE = "encryption_key.json"

# Encryption Setup 
RAW_ENCRYPTION_KEY = RagEncryptionClient.get_or_create_encryption_key(KEY_FILE)
APPROXIMATION_FACTOR = 1.5  # Choose an appropriate approximation factor

rag_client = RagEncryptionClient(
    encryption_key=RAW_ENCRYPTION_KEY,
    approximation_factor=APPROXIMATION_FACTOR
)

# Set up Cohere client
cohere_client = cohere.Client(COHERE_API_KEY)

# Connect to Zilliz Cloud
connections.connect(
    uri=ZILLIZ_ENDPOINT,
    token=ZILLIZ_TOKEN
)

# Load or create the collection
collection_name = "Encrypted_Data_March_2025" 
client = MilvusClient(
    uri=ZILLIZ_ENDPOINT,
    token=ZILLIZ_TOKEN
)
collection = Collection(collection_name)
collection.load()

    
# Function to extract text from a PDF document through a URL (No changes needed)
def extract_pdf_url(document_url):
    converter = DocumentConverter()
    converted_document = converter.convert(document_url)
    text_content = converted_document.document.export_to_markdown()
    return text_content


# Function to get embeddings using Cohere (No changes needed)
def get_embeddings(text):
    response = cohere_client.embed(
        model='embed-english-light-v3.0',
        texts=[text],
        truncate='RIGHT',
        input_type='search_document',
    )
    time.sleep(0.5)
    return response.embeddings[0]


# Function to chunk text (No changes needed)
def chunk(text):
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=600,
        chunk_overlap=20,
        length_function=len,
        is_separator_regex=False,
    )
    texts = text_splitter.create_documents([text])
    chunk_texts = [doc.page_content for doc in texts]
    return chunk_texts


def get_query_embedding(query):
    response = cohere_client.embed(
        model='embed-english-light-v3.0',
        texts=[query],  # Input the query directly as a list
        input_type='search_query',
        truncate='RIGHT',
    )
    return response.embeddings[0]  # Return the embedding


# Function to format search results (Modified to decrypt chunk_text)
def format_search_results(search_results, rag_client):
    formatted = []
    for i, hit in enumerate(search_results[0], 1):
        entity = hit.entity
        # Access fields directly from the entity
        base64_encoded_payload_string = getattr(entity, 'chunk_text', 'No text available')
        
        # Get encrypted metadata fields
        encoded_source_url = getattr(entity, 'source_url', 'N/A')
        encoded_upload_date = getattr(entity, 'upload_date', 'N/A')
        
        # Decrypt metadata fields with robust handling
        try:
            # Decrypt source URL
            if encoded_source_url != 'N/A':
                try:
                    # Fix potential base64 padding issues
                    padding_needed = len(encoded_source_url) % 4
                    if padding_needed:
                        encoded_source_url += '=' * (4 - padding_needed)
                        
                    encrypted_source_url = base64.b64decode(encoded_source_url)
                    source_url = rag_client.decrypt_deterministic_text(encrypted_source_url)
                except Exception as e:
                    source_url = f"URL Decryption Error: {str(e)[:50]}"
            else:
                source_url = 'N/A'
                
            # Decrypt upload date
            if encoded_upload_date != 'N/A':
                try:
                    # Fix potential base64 padding issues
                    padding_needed = len(encoded_upload_date) % 4
                    if padding_needed:
                        encoded_upload_date += '=' * (4 - padding_needed)
                        
                    encrypted_upload_date = base64.b64decode(encoded_upload_date)
                    upload_date = rag_client.decrypt_deterministic_text(encrypted_upload_date)
                except Exception as e:
                    upload_date = f"Date Decryption Error: {str(e)[:50]}"
            else:
                upload_date = 'N/A'
        except Exception as e:
            source_url = f"Metadata Error: {str(e)[:50]}"
            upload_date = f"Metadata Error: {str(e)[:50]}"


        # Base64 decode and decrypt the chunk text payload
        try:
            encrypted_payload_bytes = base64.b64decode(base64_encoded_payload_string)
            iv_bytes_text = encrypted_payload_bytes[:12]
            tag_bytes = encrypted_payload_bytes[12:28]
            encrypted_chunk_text = encrypted_payload_bytes[28:]
            chunk_text = rag_client.decrypt_text(encrypted_chunk_text, iv_bytes_text, tag_bytes)
        except Exception as e:
            chunk_text = f"Chunk Decryption Error: {e}"

        # Clean up newline characters
        cleaned_text = chunk_text.replace('\\n', '\n')

        formatted.append(f"""
Result {i} (Similarity Score: {1 - hit.distance:.2f}):
------------------------------------------------------------------
Source URL: {source_url}
Upload Date: {upload_date}

Text Content (Decrypted):
{cleaned_text}
------------------------------------------------------------------
""")
    return "\n".join(formatted)



def perform_single_vector_search(query_embedding, rag_client): # RagEncryptionClient instance is now passed here
    encrypted_query_embedding, _ = rag_client.encrypt_vector(query_embedding) # Encrypt query embedding
    search_results = collection.search(
        data=[encrypted_query_embedding], # Use encrypted query embedding for search
        anns_field="vector",
        param={
            "metric_type": "COSINE",
            "params": {"nprobe": 10}
        },
        limit=5,
        output_fields=["chunk_text", "source_url", "upload_date"] # Retrieve chunk_text_iv as well
    )
    return format_search_results(search_results, rag_client) # Pass rag_client to format_search_results

# Helper function for filtering search results
def _process_filter_template(expr, params, rag_client):
    """
    Process a filter expression template, encrypting parameter values.
    
    Args:
        expr (str): Filter expression with placeholders (e.g., "field == {value}")
        params (dict): Parameters to substitute
        rag_client (RagEncryptionClient): Encryption client
        
    Returns:
        str: Processed filter expression with encrypted values
    """
    encrypted_params = {}
    
    for key, value in params.items():
        # Handle string values - encrypt deterministically
        if isinstance(value, str):
            encrypted_value = rag_client.encrypt_deterministic_text(value)
            encrypted_params[key] = f"'{base64.b64encode(encrypted_value).decode('utf-8')}'"
            
        # Handle lists for IN operator
        elif isinstance(value, list) and all(isinstance(item, str) for item in value):
            encrypted_values = []
            for item in value:
                encrypted_item = rag_client.encrypt_deterministic_text(item)
                encrypted_values.append(f"'{base64.b64encode(encrypted_item).decode('utf-8')}'")
            encrypted_params[key] = f"[{', '.join(encrypted_values)}]"
            
        # Non-string values pass through unchanged (numbers, etc.)
        else:
            encrypted_params[key] = value
            
    # Format the expression with encrypted parameters
    return expr.format(**encrypted_params)

# Helper function to build a filter expression
def _build_filter_expression(filters, logic="AND", rag_client=None):
    """
    Build a filter expression from structured filter conditions.
    
    Args:
        filters (list): List of filter conditions, each a dict with:
            - "field": Field name to filter on
            - "op": Operation (==, !=, >, <, >=, <=, IN, LIKE, etc.)
            - "value": Value to filter for
        logic (str): Logic to combine filters ("AND" or "OR")
        rag_client (RagEncryptionClient): Encryption client
        
    Returns:
        str: Combined filter expression
    """
    if not filters:
        return None
        
    conditions = []
    for filter_item in filters:
        field = filter_item.get("field")
        op = filter_item.get("op", "==")
        value = filter_item.get("value")
        
        if field is None or value is None:
            continue
            
        # Handle different operators
        if op.upper() == "IN":
            # List membership operator
            if not isinstance(value, list):
                value = [value]
                
            # Encrypt each value in the list for string values
            encrypted_values = []
            for item in value:
                if isinstance(item, str):
                    encrypted_item = rag_client.encrypt_deterministic_text(item)
                    encoded_item = base64.b64encode(encrypted_item).decode('utf-8')
                    encrypted_values.append(f"'{encoded_item}'")
                else:
                    encrypted_values.append(str(item))
                    
            conditions.append(f"{field} IN [{', '.join(encrypted_values)}]")
            
        elif op.upper() == "LIKE" and isinstance(value, str):
            # Note: LIKE with deterministic encryption only works for exact matches
            # Pattern matching won't work as expected since the entire string is encrypted
            encrypted_value = rag_client.encrypt_deterministic_text(value)
            encoded_value = base64.b64encode(encrypted_value).decode('utf-8')
            conditions.append(f"{field} == '{encoded_value}'")  # Convert to exact match
            
        elif isinstance(value, str):
            # String comparison - encrypt deterministically
            encrypted_value = rag_client.encrypt_deterministic_text(value)
            encoded_value = base64.b64encode(encrypted_value).decode('utf-8')
            conditions.append(f"{field} {op} '{encoded_value}'")
            
        else:
            # Non-string values (numeric, etc.)
            conditions.append(f"{field} {op} {value}")
    
    # Combine all conditions with the specified logic
    if conditions:
        return f" {logic} ".join(conditions)
    return None

# Function to perform vector search with metadata filtering
def search_with_metadata_filter(query, filter_options, rag_client):
    """
    Perform vector search with advanced metadata filtering capabilities.
    
    Args:
        query (str): The search query
        filter_options (dict): Filter options with flexible syntax:
            - "expr": Filter expression template with placeholders (e.g., "source_url == {url}")
            - "params": Dict of parameters for template (e.g., {"url": "https://example.com"})
            - OR
            - "filters": List of filter conditions to combine with logical operators
        rag_client (RagEncryptionClient): RAG encryption client instance
    
    Returns:
        str: Formatted search results
    """
    # Get and encrypt query embedding
    query_embedding = get_query_embedding(query)
    encrypted_query_embedding, _ = rag_client.encrypt_vector(query_embedding)
    
    # Prepare search parameters
    search_params = {
        "data": [encrypted_query_embedding],
        "anns_field": "vector",
        "param": {"metric_type": "COSINE", "params": {"nprobe": 10}},
        "limit": 5,
        "output_fields": ["chunk_text", "source_url", "upload_date", "vector_icl"]
    }
    
    # Process filter expression based on provided options
    if isinstance(filter_options, dict):
        # Handle templated expressions with parameters
        if "expr" in filter_options and "params" in filter_options:
            search_params["expr"] = _process_filter_template(
                filter_options["expr"], 
                filter_options["params"], 
                rag_client
            )
        
        # Handle structured filter conditions
        elif "filters" in filter_options:
            filter_expr = _build_filter_expression(
                filter_options["filters"],
                filter_options.get("logic", "AND"),
                rag_client
            )
            if filter_expr:
                search_params["expr"] = filter_expr
    
    # Execute search with filters
    search_results = collection.search(**search_params)
    return format_search_results(search_results, rag_client)

# Function to process data 
def process_data(data, source_url, rag_client):
    processed_data = []
    chunks = chunk(data)
    # Process each chunk
    for chunk_text in chunks:
        # Encrypt chunk text (standard encryption)
        ciphertext_text_bytes, iv_bytes, tag_bytes = rag_client.encrypt_text(chunk_text)

        # Concatenate IV, tag, and ciphertext into a single byte array (header embedding)
        encrypted_payload_bytes = iv_bytes + tag_bytes + ciphertext_text_bytes

        # Base64 encode the combined payload bytes for storing in Zilliz
        base64_encoded_payload = base64.b64encode(encrypted_payload_bytes).decode('utf-8')

        # Deterministically encrypt metadata fields
        encrypted_source_url = rag_client.encrypt_deterministic_text(source_url)
        current_date = time.strftime("%Y-%m-%d")
        encrypted_upload_date = rag_client.encrypt_deterministic_text(current_date)
        
        # Base64 encode encrypted metadata for storage
        encoded_source_url = base64.b64encode(encrypted_source_url).decode('utf-8')
        encoded_upload_date = base64.b64encode(encrypted_upload_date).decode('utf-8')

        embedding = get_embeddings(chunk_text)
        # Encrypt vector embedding (searchable encryption)
        encrypted_embedding_list, paired_icl_info = rag_client.encrypt_vector(embedding)

        chunk_dict = {
            "source_url": encoded_source_url,  # Store deterministically encrypted source URL
            "chunk_text": base64_encoded_payload,  # Store Base64 encoded combined payload string
            "upload_date": encoded_upload_date,  # Store deterministically encrypted upload date
            "vector": encrypted_embedding_list
        }
        processed_data.append(chunk_dict)
    return processed_data


# Function to process data and ingest into the database (Modified to pass RagEncryptionClient)
def process_and_ingest_data(url, rag_client): # RagEncryptionClient instance is now passed here
    # Extract text from the URL
    text_data = extract_pdf_url(url)
    # Process data
    processed_data = process_data(text_data, url, rag_client) # Pass rag_client
    # Insert data into Zilliz Cloud collection
    res = client.insert(
        collection_name=collection_name,
        data=processed_data
    )
    return res


# Function to handle the vector search (Modified to pass RagEncryptionClient)
def search_query(query, rag_client): # RagEncryptionClient instance is now passed here
    # Get query embedding
    query_embedding = get_query_embedding(query)
    # Perform vector search
    search_results = perform_single_vector_search(query_embedding, rag_client) # Pass rag_client
    # Return the results
    return search_results

