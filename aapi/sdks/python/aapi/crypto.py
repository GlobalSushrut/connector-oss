import json
from typing import Optional, Tuple, Dict, Any
import hashlib

try:
    import canonicaljson  # type: ignore
except Exception as e:  # pragma: no cover
    canonicaljson = None  # type: ignore
    _canonicaljson_import_error = e
else:
    _canonicaljson_import_error = None

try:
    from nacl.signing import SigningKey, VerifyKey  # type: ignore
    from nacl.encoding import HexEncoder  # type: ignore
except Exception as e:  # pragma: no cover
    SigningKey = None  # type: ignore
    VerifyKey = None  # type: ignore
    HexEncoder = None  # type: ignore
    _pynacl_import_error = e
else:
    _pynacl_import_error = None

from .models import Vakya

class KeyPair:
    """Ed25519 Key Pair for signing VĀKYA requests"""
    def __init__(self, signing_key: SigningKey):
        self.signing_key = signing_key
        self.verify_key = signing_key.verify_key

    @classmethod
    def generate(cls) -> "KeyPair":
        """Generate a new random key pair"""
        _require_crypto_deps()
        return cls(SigningKey.generate())

    @classmethod
    def from_seed(cls, seed_hex: str) -> "KeyPair":
        """Load key pair from a hex seed"""
        _require_crypto_deps()
        return cls(SigningKey(seed_hex, encoder=HexEncoder))

    @property
    def public_key_hex(self) -> str:
        """Get public key in hex format"""
        return self.verify_key.encode(encoder=HexEncoder).decode('utf-8')

    @property
    def private_key_hex(self) -> str:
        """Get private key (seed) in hex format"""
        return self.signing_key.encode(encoder=HexEncoder).decode('utf-8')

    def sign(self, message: bytes) -> str:
        """Sign a message and return hex signature"""
        signed = self.signing_key.sign(message)
        return signed.signature.hex()


class VakyaSigner:
    """Signer for VĀKYA requests"""
    def __init__(self, key_pair: KeyPair, key_id: str):
        self.key_pair = key_pair
        self.key_id = key_id

    def sign_vakya(self, vakya: Vakya) -> Tuple[str, str]:
        """
        Sign a VĀKYA request.
        Returns (signature_hex, key_id)
        """
        # 1. Canonicalize the VĀKYA to JSON (RFC 8785)
        # We convert the Pydantic model to a dict, explicitly excluding None fields
        # if they were excluded in the Rust implementation serialization.
        # However, Pydantic's model_dump(exclude_none=True) usually matches serde's skip_serializing_if="Option::is_none"
        
        vakya_dict = vakya.model_dump(exclude_none=True, mode='json')
        
        # Ensure semantic version is serialized as string if needed, or dict if that's what Rust does.
        # In Rust: SemanticVersion is a struct.
        # In Python models.py: SemanticVersion is a BaseModel.
        # So model_dump will produce a dict. Let's check Rust serialization.
        # Rust `SemanticVersion` derives Serialize, so it serializes as a struct (JSON object).
        # Python `model_dump(mode='json')` should be fine.
        
        _require_crypto_deps()

        # Canonicalize using canonicaljson (JCS compliant)
        canonical_bytes = canonicaljson.encode_canonical_json(vakya_dict)
        
        # 2. Sign the canonical bytes
        signature = self.key_pair.sign(canonical_bytes)
        
        return signature, self.key_id

    def verify_vakya(self, vakya: Vakya, signature_hex: str, public_key_hex: str) -> bool:
        """Verify a VĀKYA signature"""
        try:
            _require_crypto_deps()
            verify_key = VerifyKey(public_key_hex, encoder=HexEncoder)
            
            vakya_dict = vakya.model_dump(exclude_none=True, mode='json')
            canonical_bytes = canonicaljson.encode_canonical_json(vakya_dict)
            
            verify_key.verify(canonical_bytes, bytes.fromhex(signature_hex))
            return True
        except Exception:
            return False


def _require_crypto_deps() -> None:
    if _canonicaljson_import_error is not None:
        raise RuntimeError(
            "Missing dependency 'canonicaljson'. Install with: pip install canonicaljson"
        ) from _canonicaljson_import_error
    if _pynacl_import_error is not None:
        raise RuntimeError(
            "Missing dependency 'pynacl'. Install with: pip install pynacl"
        ) from _pynacl_import_error
