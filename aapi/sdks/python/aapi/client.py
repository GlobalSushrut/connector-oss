import httpx
from typing import Optional, Dict, Any, List, Protocol

from .models import Vakya


class _Signer(Protocol):
    def sign_vakya(self, vakya: Vakya):
        ...

class AapiClient:
    """Client for interacting with the AAPI Gateway"""
    
    def __init__(
        self, 
        base_url: str = "http://localhost:8080",
        timeout: float = 30.0,
        signer: Optional[_Signer] = None
    ):
        self.base_url = base_url
        self.timeout = timeout
        self.signer = signer
        self._client = httpx.Client(base_url=base_url, timeout=timeout)

    def submit(self, vakya: Vakya) -> Dict[str, Any]:
        """
        Submit a VĀKYA request to the gateway.
        
        Args:
            vakya: The VĀKYA object to submit
            
        Returns:
            Dict containing the submission response (id, hash, status, receipt)
        """
        payload: Dict[str, Any] = {
            "vakya": vakya.model_dump(exclude_none=True, mode='json')
        }
        
        if self.signer:
            signature, key_id = self.signer.sign_vakya(vakya)
            payload["signature"] = signature
            payload["key_id"] = key_id
            
        response = self._client.post("/v1/vakya", json=payload)
        response.raise_for_status()
        return response.json()

    def get_vakya(self, vakya_id: str) -> Dict[str, Any]:
        """Get a VĀKYA record by ID"""
        response = self._client.get(f"/v1/vakya/{vakya_id}")
        response.raise_for_status()
        return response.json()

    def get_receipt(self, vakya_id: str) -> Dict[str, Any]:
        """Get a receipt for a VĀKYA"""
        response = self._client.get(f"/v1/vakya/{vakya_id}/receipt")
        response.raise_for_status()
        return response.json()

    def get_effects(self, vakya_id: str) -> List[Dict[str, Any]]:
        """Get effects for a VĀKYA"""
        response = self._client.get(f"/v1/vakya/{vakya_id}/effects")
        response.raise_for_status()
        return response.json()

    def get_merkle_root(self, tree_type: str = "vakya") -> Dict[str, Any]:
        """Get the current Merkle root"""
        response = self._client.get(f"/v1/merkle/root", params={"tree_type": tree_type})
        response.raise_for_status()
        return response.json()

    def get_inclusion_proof(self, leaf_index: int, tree_type: str = "vakya") -> Dict[str, Any]:
        """Get an inclusion proof for a leaf index"""
        response = self._client.get(
            f"/v1/merkle/proof", 
            params={"tree_type": tree_type, "leaf_index": leaf_index}
        )
        response.raise_for_status()
        return response.json()

    def health(self) -> Dict[str, Any]:
        """Check gateway health"""
        response = self._client.get("/health")
        response.raise_for_status()
        return response.json()

    def close(self):
        """Close the underlying HTTP client"""
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
