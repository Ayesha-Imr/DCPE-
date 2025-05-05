import os
import uuid
import time
import base64
import numpy as np
from dotenv import load_dotenv
from pymilvus import MilvusClient, connections, Collection, FieldSchema, CollectionSchema, DataType, utility
from langchain_text_splitters import RecursiveCharacterTextSplitter
import cohere
from docling.document_converter import DocumentConverter
from phe import paillier
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import struct

# Load environment variables
load_dotenv()

# Load API keys and endpoints
COHERE_API_KEY = os.getenv('COHERE_API_KEY')
ZILLIZ_ENDPOINT = os.getenv('ZILLIZ_ENDPOINT')
ZILLIZ_TOKEN = os.getenv('ZILLIZ_TOKEN')

# Set up Cohere client
cohere_client = cohere.Client(COHERE_API_KEY)

# Connect to Zilliz Cloud
connections.connect(
    uri=ZILLIZ_ENDPOINT,
    token=ZILLIZ_TOKEN
)

# Set up encryption components
# AES-GCM Encryption for text data
aes_key = os.getenv('AES_KEY', 'ThisIsMy32ByteKeyForAESGCM12345!').encode()  # 32 bytes AES key
aesgcm = AESGCM(aes_key)

# Generate Paillier keys (public and private)
public_key, private_key = paillier.generate_paillier_keypair(n_length=1024)

# Collection name for encrypted data
encrypted_collection_name = "Paillier_Encrypted_Data"

# Client for Milvus operations
client = MilvusClient(
    uri=ZILLIZ_ENDPOINT,
    token=ZILLIZ_TOKEN
)

# AES Encryption functions for text data
def encrypt_text(text):
    """Encrypt text using AES-GCM."""
    nonce = os.urandom(12)  # Generate a unique nonce for each encryption
    ciphertext = aesgcm.encrypt(nonce, text.encode('utf-8'), None)
    encrypted_data = nonce + ciphertext  # Combine nonce and ciphertext
    return base64.b64encode(encrypted_data).decode('utf-8')  # Base64 encoding for storage

def decrypt_text(encrypted_text):
    """Decrypt text using AES-GCM."""
    decoded_data = base64.b64decode(encrypted_text)
    nonce = decoded_data[:12]
    ciphertext = decoded_data[12:]
    decrypted_text = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted_text.decode('utf-8')

# Compression functions for normalization parameters
def compress_norm_params(min_val, max_val):
    """Compress normalization parameters to a short string."""
    # Convert to base64 string (16 bytes for each number)
    min_bytes = struct.pack('!Q', min_val & ((1 << 64) - 1))  # Lower 64 bits
    max_bytes = struct.pack('!Q', max_val & ((1 << 64) - 1))  # Lower 64 bits
    
    # For very large numbers, we might need to store more bits
    min_bytes2 = struct.pack('!Q', (min_val >> 64) & ((1 << 64) - 1))  # Upper bits
    max_bytes2 = struct.pack('!Q', (max_val >> 64) & ((1 << 64) - 1))  # Upper bits
    
    all_bytes = min_bytes + max_bytes + min_bytes2 + max_bytes2
    return base64.b64encode(all_bytes).decode('utf-8')

def decompress_norm_params(compressed_str):
    """Decompress normalization parameters from string."""
    all_bytes = base64.b64decode(compressed_str)
    
    # Extract the packed values
    min_val_lower = struct.unpack('!Q', all_bytes[0:8])[0]
    max_val_lower = struct.unpack('!Q', all_bytes[8:16])[0]
    min_val_upper = struct.unpack('!Q', all_bytes[16:24])[0]
    max_val_upper = struct.unpack('!Q', all_bytes[24:32])[0]
    
    # Reconstruct the full values
    min_val = min_val_lower | (min_val_upper << 64)
    max_val = max_val_lower | (max_val_upper << 64)
    
    return min_val, max_val

# Vector encryption functions
def encrypt_vector(embedding):
    """Encrypt vector using Paillier homomorphic encryption."""
    # Scale the embeddings to work better with Paillier
    scaled = [int(round(x * 1000)) for x in embedding]
    
    # Encrypt each component
    encrypted_vector = [public_key.encrypt(x) for x in scaled]
    
    return encrypted_vector

def serialize_encrypted_vector(encrypted_vector):
    """Serialize encrypted vector for storage in Zilliz/Milvus."""
    # Extract ciphertexts
    ciphertexts = [x.ciphertext() for x in encrypted_vector]
    
    # Normalize to float range for vector database
    if len(ciphertexts) > 0:
        max_val = max(ciphertexts)
        min_val = min(ciphertexts)
        range_val = max_val - min_val
        if range_val == 0:
            normalized = [0.0 for _ in ciphertexts]
        else:
            normalized = [2 * ((x - min_val) / range_val) - 1 for x in ciphertexts]
    else:
        normalized = []
        min_val = 0
        max_val = 0
    
    # Compress normalization parameters
    compressed_params = compress_norm_params(min_val, max_val)
    
    return normalized, compressed_params

def deserialize_encrypted_vector(normalized_vector, compressed_params):
    """Convert back from normalized float to original ciphertext integers."""
    min_val, max_val = decompress_norm_params(compressed_params)
    
    # Denormalize to original ciphertext range
    if max_val != min_val:
        denormalized = [int(((x + 1) / 2) * (max_val - min_val) + min_val) for x in normalized_vector]
    else:
        denormalized = [min_val for _ in normalized_vector]
    
    # Recreate Paillier encrypted numbers
    recreated = [paillier.EncryptedNumber(public_key, x) for x in denormalized]
    return recreated

# Initialize or get the collection
def initialize_collection():
    """Initialize or get the encrypted vector collection."""
    # Define fields for the collection
    if not utility.has_collection(encrypted_collection_name):
        # Define the schema
        fields = [
            FieldSchema(name="id", dtype=DataType.VARCHAR, max_length=100, is_primary=True),
            FieldSchema(name="encrypted_source_url", dtype=DataType.VARCHAR, max_length=1024),
            FieldSchema(name="encrypted_chunk_text", dtype=DataType.VARCHAR, max_length=10000),
            FieldSchema(name="encrypted_upload_date", dtype=DataType.VARCHAR, max_length=100),
            FieldSchema(name="vector", dtype=DataType.FLOAT_VECTOR, dim=384),  # Cohere embed-english-light-v3.0 dimension
            FieldSchema(name="norm_params", dtype=DataType.VARCHAR, max_length=512)  # For encryption parameters
        ]
        
        schema = CollectionSchema(fields, description="Encrypted vector search collection")
        collection = Collection(name=encrypted_collection_name, schema=schema)
        
        # Create index for vector search
        index_params = {
            "metric_type": "IP",  # Inner Product for homomorphic dot product
            "index_type": "AUTOINDEX",
            "params": {}
        }
        collection.create_index(field_name="vector", index_params=index_params)
        collection.load()
        print(f"Created new collection: {encrypted_collection_name}")
    else:
        collection = Collection(encrypted_collection_name)
        collection.load()
        print(f"Loaded existing collection: {encrypted_collection_name}")
    
    return collection

# Function to extract text from a PDF document through a URL
def extract_pdf_url(document_url):
    """Extract text from a PDF document through a URL."""
    # Initialize the DocumentConverter
    converter = DocumentConverter()

    # Convert the document from the URL
    converted_document = converter.convert(document_url)

    # Extract text content from the converted document
    text_content = converted_document.document.export_to_markdown()

    # Return extracted content
    return text_content

# Function to get embeddings using Cohere
def get_embeddings(text):
    """Generate embeddings for text using Cohere."""
    response = cohere_client.embed(
        model='embed-english-light-v3.0',
        texts=[text],
        truncate='RIGHT',
        input_type='search_document',
    )
    time.sleep(0.5)
    return response.embeddings[0]

# Function to get query embeddings
def get_query_embedding(query):
    """Generate embeddings for query using Cohere."""
    response = cohere_client.embed(
        model='embed-english-light-v3.0',
        texts=[query],
        input_type='search_query',
        truncate='RIGHT',
    )
    return response.embeddings[0]

# Function to chunk text
def chunk(text):
    """Split text into smaller chunks."""
    # Initialize the text splitter
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=600,
        chunk_overlap=20,
        length_function=len,
        is_separator_regex=False,
    )

    # Create documents from the text
    texts = text_splitter.create_documents([text])

    # Extract the chunked text from each Document and store it in a list
    chunk_texts = [doc.page_content for doc in texts]

    return chunk_texts

# Function to process data with encryption
def process_data(data, source_url):
    """Process data with encryption before insertion."""
    processed_data = []
    chunks = chunk(data)
    upload_date = time.strftime("%Y-%m-%d %H:%M:%S")
    
    # Process each chunk
    for chunk_text in chunks:
        # Generate embeddings
        embedding = get_embeddings(chunk_text)
        
        # Encrypt embeddings with Paillier
        encrypted_embedding = encrypt_vector(embedding)
        
        # Serialize for Zilliz storage
        normalized_embedding, compressed_params = serialize_encrypted_vector(encrypted_embedding)
        
        # Encrypt text data with AES
        encrypted_chunk_text = encrypt_text(chunk_text)
        encrypted_source_url = encrypt_text(source_url)
        encrypted_upload_date = encrypt_text(upload_date)
        
        # Create document entry
        chunk_dict = {
            "encrypted_source_url": encrypted_source_url,
            "encrypted_chunk_text": encrypted_chunk_text,
            "encrypted_upload_date": encrypted_upload_date,
            "vector": normalized_embedding,
            "norm_params": compressed_params
        }
        
        processed_data.append(chunk_dict)
    
    return processed_data

# Function to process data and ingest into the database
def process_and_ingest_data(url):
    """Extract, process, encrypt, and insert data into the database."""
    # Initialize collection
    collection = initialize_collection()
    
    # Extract text from the URL
    text_data = extract_pdf_url(url)

    # Process data with encryption
    processed_data = process_data(text_data, url)
    
    # Insert data into Zilliz Cloud collection
    data_list = []
    for item in processed_data:
        data_list.append(item)
    
    res = collection.insert(data_list)
    print(f"Inserted {len(processed_data)} encrypted chunks into the collection")
    return res

# Function to format search results
def format_search_results(search_results):
    """Format search results with decrypted content."""
    formatted = []
    for i, hit in enumerate(search_results, 1):
        entity = hit.entity
        
        # Access attributes directly instead of using get()
        encrypted_chunk_text = getattr(entity, 'encrypted_chunk_text', '')
        encrypted_source_url = getattr(entity, 'encrypted_source_url', '')
        encrypted_upload_date = getattr(entity, 'encrypted_upload_date', '')
        
        # Decrypt the data
        chunk_text = decrypt_text(encrypted_chunk_text) if encrypted_chunk_text else 'No text available'
        source_url = decrypt_text(encrypted_source_url) if encrypted_source_url else 'N/A'
        upload_date = decrypt_text(encrypted_upload_date) if encrypted_upload_date else 'N/A'
        
        formatted.append(f"""
Result {i} (Similarity Score: {hit.score:.4f}):
------------------------------------------------------------------
Source URL: {source_url}
Upload Date: {upload_date}

Text Content:
{chunk_text}
------------------------------------------------------------------
""")
    return "\n".join(formatted)

# Homomorphic similarity search
def homomorphic_search(query, top_k=5):
    """
    Search using homomorphic encryption properties.
    Both query and database vectors are encrypted.
    """
    # Load the collection
    collection = Collection(encrypted_collection_name)
    collection.load()
    
    # 1. Get query embedding
    query_embedding = get_query_embedding(query)
    
    # 2. Encrypt query embedding with Paillier
    encrypted_query = encrypt_vector(query_embedding)
    
    # 3. Normalize for storage format
    normalized_query, _ = serialize_encrypted_vector(encrypted_query)
    
    # 4. Search in the vector database
    search_params = {
        "metric_type": "IP",  # Inner Product for homomorphic dot product
        "params": {"nprobe": 20},
    }
    
    search_results = collection.search(
        data=[normalized_query],
        anns_field="vector",
        param=search_params,
        limit=top_k,
        output_fields=["encrypted_chunk_text", "encrypted_source_url", "encrypted_upload_date", "norm_params"],
    )
    
    # 5. Format and decrypt results
    formatted_results = format_search_results(search_results[0])
    return formatted_results

# Main search function
def search_query(query, top_k=5):
    """Search with query text and return formatted results."""
    # Perform homomorphic search
    search_results = homomorphic_search(query, top_k)
    return search_results

# Example usage
if __name__ == "__main__":
    print("Encrypted Vector Search Pipeline")
    print("--------------------------------")
    choice = input("Choose operation: (1) Ingest Document, (2) Search: ")
    
    if choice == "1":
        url = input("Enter document URL: ")
        process_and_ingest_data(url)
    elif choice == "2":
        query = input("Enter search query: ")
        results = search_query(query)
        print("\nSearch Results:")
        print(results)
    else:
        print("Invalid choice!")