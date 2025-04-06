# key_provider_module.py
# Interface for external key providers to support client-side KMS integration

from abc import ABC, abstractmethod
from typing import Optional
import os
import json
import base64

class KeyProvider(ABC):
    """Abstract interface for external key providers."""
    
    @abstractmethod
    def get_key(self, key_id: str = None) -> bytes:
        """Retrieve a key from the provider.
        
        Args:
            key_id (str, optional): The identifier for the key to retrieve
            
        Returns:
            bytes: The raw key material
        
        Raises:
            KeyError: If the key is not found or cannot be accessed
        """
        pass
       
    @abstractmethod
    def store_key(self, key_material: bytes, key_id: str = None) -> str:
        """Store a key in the provider.
        
        Args:
            key_material (bytes): The raw key to store
            key_id (str, optional): Optional identifier for the key
            
        Returns:
            str: The identifier assigned to the stored key
        
        Raises:
            ValueError: If the key material is invalid
            RuntimeError: If the key cannot be stored
        """
        pass


# Add this implementation to your KeyProvider module

class FileKeyProvider(KeyProvider):
    """Simple key provider that stores keys in a JSON file."""
    
    def __init__(self, key_file_path: str):
        """Initialize with path to key file."""
        self.key_file_path = key_file_path
        os.makedirs(os.path.dirname(key_file_path), exist_ok=True)
        
    def get_key(self, key_id: str = None) -> bytes:
        """Get a key by ID, or default key if no ID provided."""
        try:
            if os.path.exists(self.key_file_path):
                with open(self.key_file_path, 'r') as f:
                    key_data = json.load(f)
                    
                # If key_id is provided, look for that specific key
                if key_id and key_id in key_data:
                    return base64.b64decode(key_data[key_id])
                # Otherwise return the default key
                elif "key" in key_data:
                    return base64.b64decode(key_data["key"])
                    
            # If we get here, the file doesn't exist or doesn't have the key
            raise KeyError(f"Key not found: {key_id if key_id else 'default'}")
            
        except Exception as e:
            raise KeyError(f"Error retrieving key: {str(e)}")
            
    def store_key(self, key_material: bytes, key_id: str = None) -> str:
        """Store a key with optional ID."""
        try:
            # Load existing keys if any
            key_data = {}
            if os.path.exists(self.key_file_path):
                with open(self.key_file_path, 'r') as f:
                    key_data = json.load(f)
            
            # Use provided key_id or "key" as default
            actual_key_id = key_id or "key"
            key_data[actual_key_id] = base64.b64encode(key_material).decode('utf-8')
            
            # Write back to file
            with open(self.key_file_path, 'w') as f:
                json.dump(key_data, f)
                
            return actual_key_id
            
        except Exception as e:
            raise RuntimeError(f"Error storing key: {str(e)}")