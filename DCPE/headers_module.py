# headers_module.py

from enum import Enum
from typing import Tuple, Union, NamedTuple
from DCPE.exceptions_module import InvalidInputError
from DCPE.crypto_module import AuthHash

# EDEK Types as Enum
class EdekType(str, Enum):
    STANDALONE = "Standalone"
    SAAS_SHIELD = "SaasShield"
    DATA_CONTROL_PLATFORM = "DataControlPlatform"

# Payload Types as Enum
class PayloadType(str, Enum):
    DETERMINISTIC_FIELD = "DeterministicField"
    VECTOR_METADATA = "VectorMetadata"
    STANDARD_EDEK = "StandardEdek"

class KeyIdHeader:
    """Represents the Key ID Header."""
    def __init__(self, key_id: int, edek_type: EdekType, payload_type: PayloadType):
        if not isinstance(key_id, int):
            raise TypeError("key_id must be an integer")
        if not isinstance(edek_type, EdekType):
            raise TypeError("edek_type must be an EdekType enum value")
        if not isinstance(payload_type, PayloadType):
            raise TypeError("payload_type must be a PayloadType enum value")
        self.key_id = key_id
        self.edek_type = edek_type
        self.payload_type = payload_type

    @classmethod
    def create_header(cls, edek_type: EdekType, payload_type: PayloadType, key_id: int):
        """Creates a KeyIdHeader instance."""
        return cls(key_id=key_id, edek_type=edek_type, payload_type=payload_type)

    def write_to_bytes(self) -> bytes:
        """Serializes KeyIdHeader to bytes (simplified byte packing)."""
        return (
            self.key_id.to_bytes(4, byteorder='big') +
            bytes([self._encode_type_byte()]) +
            bytes([0]) # Padding byte
        )

    @classmethod
    def parse_from_bytes(cls, header_bytes: bytes) -> 'KeyIdHeader':
        """Parses bytes and reconstructs a KeyIdHeader instance (simplified byte packing)."""
        if len(header_bytes) != 6:
            raise InvalidInputError(f"Header bytes must be 6 bytes long, got {len(header_bytes)}")

        key_id = int.from_bytes(header_bytes[0:4], byteorder='big')
        type_byte = header_bytes[4]
        padding_byte = header_bytes[5]

        if padding_byte != 0:
            raise InvalidInputError(f"Padding byte in header is not zero: {padding_byte}")

        edek_type, payload_type = cls._decode_type_byte(type_byte)

        return cls(key_id=key_id, edek_type=edek_type, payload_type=payload_type)


    def _encode_type_byte(self) -> int:
        """Encodes EdekType and PayloadType into a single byte (simplified)."""
        edek_numeric = list(EdekType).index(self.edek_type) << 4  # Shift EdekType to top 4 bits
        payload_numeric = list(PayloadType).index(self.payload_type) # PayloadType in bottom 4 bits
        return edek_numeric | payload_numeric


    @classmethod
    def _decode_type_byte(cls, type_byte: int) -> Tuple[EdekType, PayloadType]:
        """Decodes the type byte back to EdekType and PayloadType (simplified)."""
        edek_type_numeric = (type_byte & 0xF0) # Extract top 4 bits for EdekType
        payload_type_numeric = (type_byte & 0x0F) # Extract bottom 4 bits for PayloadType

        try:
            edek_type = list(EdekType)[edek_type_numeric >> 4]
        except IndexError:
            raise InvalidInputError(f"Invalid EdekType numeric value: {edek_type_numeric >> 4}")
        try:
            payload_type = list(PayloadType)[payload_type_numeric]
        except IndexError:
            raise InvalidInputError(f"Invalid PayloadType numeric value: {payload_type_numeric}")

        return edek_type, payload_type


class VectorMetadata(NamedTuple):
    """Represents Vector Metadata, including IV and AuthHash."""
    key_id_header: KeyIdHeader
    iv: bytes
    auth_hash: AuthHash 


def encode_vector_metadata(key_id_header: KeyIdHeader, iv: bytes, auth_hash: AuthHash) -> bytes:
    """Encodes vector metadata along with the KeyIdHeader into bytes."""
    return (
        key_id_header.write_to_bytes() +
        iv +
        auth_hash.get_bytes()
    )


def decode_version_prefixed_value(value_bytes: bytes) -> Tuple[KeyIdHeader, bytes]:
    """Decodes a byte stream with a prefixed KeyIdHeader, returning the KeyIdHeader and remaining bytes."""
    if len(value_bytes) < 6:
        raise InvalidInputError("Value bytes too short to contain KeyIdHeader")

    header_bytes = value_bytes[:6]
    remaining_bytes = value_bytes[6:]
    key_id_header = KeyIdHeader.parse_from_bytes(header_bytes)
    return key_id_header, remaining_bytes