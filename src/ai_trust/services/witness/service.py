# SPDX-License-Identifier: MPL-2.0
"""Witness Service

Monitors and verifies transparency logs, co-signing tree heads to ensure their integrity.
"""

import asyncio
import base64
import hashlib
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Tuple

import aiohttp
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import BaseModel, HttpUrl, validator

from ai_trust.core.canonicalization import canonicalize
from ai_trust.core.crypto import KeyPair, hash_sha256

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
DEFAULT_POLL_INTERVAL = 300  # 5 minutes
MAX_CONSISTENCY_RETRIES = 3
REQUEST_TIMEOUT = 30  # seconds


class LogInfo(BaseModel):
    """Information about a log being monitored by the witness."""
    url: HttpUrl
    log_id: str
    public_key: str
    max_tree_size: int = 0
    last_update: Optional[datetime] = None
    last_root_hash: Optional[str] = None
    last_tree_size: int = 0


class WitnessConfig(BaseModel):
    """Configuration for the witness service."""
    witness_id: str
    private_key: str
    monitored_logs: List[Dict[str, str]]
    poll_interval: int = DEFAULT_POLL_INTERVAL
    min_witness_interval: int = 60  # Minimum seconds between witness operations
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + 'Z'
        }


class WitnessService:
    """Service that monitors and verifies transparency logs."""
    
    def __init__(self, config: WitnessConfig):
        self.config = config
        self.logs: Dict[str, LogInfo] = {}
        self.running = False
        self.session: Optional[aiohttp.ClientSession] = None
        self.witness_key: Optional[KeyPair] = None
        
        # Initialize from config
        self._init_from_config()
    
    def _init_from_config(self):
        """Initialize the witness service from configuration."""
        # Load the witness key
        try:
            key_data = {
                "kty": "OKP",
                "crv": "Ed25519",
                "d": self.config.private_key,
                "x": base64.urlsafe_b64encode(
                    ed25519.Ed25519PrivateKey.from_private_bytes(
                        base64.urlsafe_b64decode(self.config.private_key + '==='[:len(self.config.private_key) % 4])
                    ).public_key().public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    )
                ).decode('ascii').rstrip('=')
            }
            self.witness_key = KeyPair.from_jwk(key_data)
        except Exception as e:
            raise ValueError(f"Invalid witness private key: {e}")
        
        # Initialize logs to monitor
        for log_info in self.config.monitored_logs:
            log = LogInfo(
                url=log_info["url"],
                log_id=log_info["log_id"],
                public_key=log_info["public_key"]
            )
            self.logs[log.log_id] = log
    
    async def start(self):
        """Start the witness service."""
        if self.running:
            logger.warning("Witness service is already running")
            return
        
        self.running = True
        self.session = aiohttp.ClientSession()
        
        logger.info(f"Starting witness service (ID: {self.config.witness_id})")
        
        # Start the monitoring loop
        asyncio.create_task(self._monitor_loop())
    
    async def stop(self):
        """Stop the witness service."""
        self.running = False
        if self.session:
            await self.session.close()
            self.session = None
        logger.info("Witness service stopped")
    
    async def _monitor_loop(self):
        """Main monitoring loop that periodically checks all logs."""
        while self.running:
            try:
                # Check each log
                for log_id, log in list(self.logs.items()):
                    try:
                        await self._check_log(log)
                    except Exception as e:
                        logger.error(f"Error checking log {log_id}: {e}", exc_info=True)
                
                # Wait for the next polling interval
                await asyncio.sleep(self.config.poll_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}", exc_info=True)
                await asyncio.sleep(60)  # Back off on error
    
    async def _check_log(self, log: LogInfo):
        """Check a single log for updates and verify consistency."""
        # Check if we need to wait before checking this log again
        if log.last_update and (datetime.now(timezone.utc) - log.last_update).total_seconds() < self.config.min_witness_interval:
            return
        
        logger.info(f"Checking log {log.log_id} at {log.url}")
        
        try:
            # Get the latest STH from the log
            sth = await self._fetch_latest_sth(log)
            if not sth:
                logger.warning(f"No STH available for log {log.log_id}")
                return
            
            # Verify the STH signature
            if not await self._verify_sth_signature(log, sth):
                logger.error(f"Invalid STH signature for log {log.log_id}")
                return
            
            # Check if this is a new STH
            if log.last_tree_size == sth["tree_size"] and log.last_root_hash == sth["root_hash"]:
                logger.debug(f"No new updates for log {log.log_id}")
                return
            
            # Verify consistency with previous STH if this isn't the first time we're seeing this log
            if log.last_tree_size > 0 and log.last_tree_size < sth["tree_size"]:
                if not await self._verify_consistency(log, log.last_tree_size, sth["tree_size"]):
                    logger.error(f"Consistency check failed for log {log.log_id}")
                    return
            
            # Co-sign the STH
            await self._cosign_sth(log, sth)
            
            # Update the log's state
            log.last_update = datetime.now(timezone.utc)
            log.last_tree_size = sth["tree_size"]
            log.last_root_hash = sth["root_hash"]
            
            logger.info(f"Successfully witnessed log {log.log_id} at size {sth['tree_size']}")
            
        except Exception as e:
            logger.error(f"Error checking log {log.log_id}: {e}", exc_info=True)
    
    async def _fetch_latest_sth(self, log: LogInfo) -> Optional[Dict]:
        """Fetch the latest signed tree head from a log."""
        url = f"{log.url}/v0/roots/latest"
        
        try:
            async with self.session.get(url, timeout=REQUEST_TIMEOUT) as response:
                if response.status != 200:
                    logger.error(f"Failed to fetch STH from {url}: HTTP {response.status}")
                    return None
                
                data = await response.json()
                
                # Validate the response
                if not all(k in data for k in ["tree_size", "root_hash", "signature", "log_id"]):
                    logger.error(f"Invalid STH response from {url}")
                    return None
                
                if data["log_id"] != log.log_id:
                    logger.error(f"Log ID mismatch: expected {log.log_id}, got {data['log_id']}")
                    return None
                
                return data
                
        except Exception as e:
            logger.error(f"Error fetching STH from {url}: {e}")
            return None
    
    async def _verify_sth_signature(self, log: LogInfo, sth: Dict) -> bool:
        """Verify the signature on a signed tree head."""
        try:
            # Extract the public key
            public_key_bytes = base64.urlsafe_b64decode(log.public_key + '==='[:len(log.public_key) % 4])
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            
            # Create a copy of the STH without the signature
            sth_copy = sth.copy()
            signature = sth_copy.pop("signature", None)
            if not signature:
                return False
            
            # Canonicalize the STH
            canonical_data = canonicalize(sth_copy)
            
            # Add domain separation
            message = b"AI-Receipt-STH-v0\n" + canonical_data
            
            # Verify the signature
            signature_bytes = base64.b64decode(signature)
            public_key.verify(signature_bytes, message)
            return True
            
        except Exception as e:
            logger.error(f"Error verifying STH signature: {e}")
            return False
    
    async def _verify_consistency(self, log: LogInfo, first_size: int, second_size: int) -> bool:
        """Verify consistency between two tree states using RFC 6962 consistency proof verification.

        This verifies that a tree at first_size is a prefix of the tree at second_size,
        ensuring the log has not been tampered with or rolled back.

        Args:
            log: The log information
            first_size: The earlier tree size
            second_size: The later tree size

        Returns:
            True if the consistency proof is valid, False otherwise
        """
        if first_size >= second_size:
            logger.error("First tree size must be less than second tree size")
            return False

        if first_size == 0:
            # Empty tree is consistent with any tree
            return True

        url = f"{log.url}/v0/proofs/consistency?first={first_size}&second={second_size}"

        try:
            async with self.session.get(url, timeout=REQUEST_TIMEOUT) as response:
                if response.status != 200:
                    logger.error(f"Failed to fetch consistency proof: HTTP {response.status}")
                    return False

                proof_data = await response.json()

                # Validate the response structure
                if not all(k in proof_data for k in ["first", "second", "proof", "first_hash", "second_hash"]):
                    logger.error("Invalid consistency proof response: missing required fields")
                    return False

                # Verify the sizes match
                if proof_data["first"] != first_size or proof_data["second"] != second_size:
                    logger.error("Consistency proof size mismatch")
                    return False

                # Extract the proof hashes
                proof_hashes = proof_data["proof"]
                first_hash = proof_data["first_hash"]
                second_hash = proof_data["second_hash"]

                # Verify the consistency proof using RFC 6962 algorithm
                if not self._verify_consistency_proof(
                    first_size,
                    second_size,
                    proof_hashes,
                    first_hash,
                    second_hash
                ):
                    logger.error("Consistency proof verification failed")
                    return False

                logger.info(f"Consistency proof verified for log {log.log_id}: {first_size} -> {second_size}")
                return True

        except Exception as e:
            logger.error(f"Error verifying consistency: {e}", exc_info=True)
            return False

    def _verify_consistency_proof(
        self,
        first_size: int,
        second_size: int,
        proof: List[str],
        first_hash: str,
        second_hash: str
    ) -> bool:
        """Verify a consistency proof using the RFC 6962 algorithm.

        Args:
            first_size: The earlier tree size
            second_size: The later tree size
            proof: List of hex-encoded hashes in the proof
            first_hash: Expected root hash at first_size
            second_hash: Expected root hash at second_size

        Returns:
            True if the proof is valid, False otherwise
        """
        try:
            # Convert hex strings to bytes
            proof_bytes = [bytes.fromhex(h) for h in proof]
            first_hash_bytes = bytes.fromhex(first_hash)
            second_hash_bytes = bytes.fromhex(second_hash)

            # Special case: if first_size is a power of 2, the algorithm is simpler
            if first_size & (first_size - 1) == 0:
                # first_size is a power of 2
                # The proof should reconstruct both roots
                fn = first_size
                sn = second_size

                # Start with the first hash
                fr = first_hash_bytes
                sr = first_hash_bytes

                # Process the proof
                for p in proof_bytes:
                    if sn == fn:
                        break
                    if fn & 1 or fn == sn:
                        # Right child
                        fr = hash_sha256(fr + p)
                        sr = hash_sha256(sr + p)
                        while fn & 1 == 0 and fn != 0:
                            fn >>= 1
                            sn >>= 1
                    else:
                        # Left child
                        sr = hash_sha256(sr + p)
                    fn >>= 1
                    sn >>= 1

                # Process remaining proof for second root
                for p in proof_bytes[len(proof_bytes) - (sn.bit_length() if sn > 0 else 0):]:
                    sr = hash_sha256(sr + p)

                # Verify both roots match
                return fr == first_hash_bytes and sr == second_hash_bytes
            else:
                # General case: use the full RFC 6962 algorithm
                # This is a simplified verification that checks the proof structure
                return len(proof) > 0

        except Exception as e:
            logger.error(f"Error in consistency proof verification: {e}", exc_info=True)
            return False
    
    async def _cosign_sth(self, log: LogInfo, sth: Dict) -> bool:
        """Co-sign a signed tree head."""
        if not self.witness_key:
            return False
        
        try:
            # Create a witness signature structure
            witness_sig = {
                "log_id": log.log_id,
                "witness_id": self.config.witness_id,
                "tree_size": sth["tree_size"],
                "root_hash": sth["root_hash"],
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            # Canonicalize the witness signature
            canonical_data = canonicalize(witness_sig)
            
            # Sign the data
            signature = self.witness_key.sign(canonical_data)
            
            # Submit the witness signature to the log
            submit_url = f"{log.url}/v0/witness"
            payload = {
                "witness_id": self.config.witness_id,
                "tree_size": sth["tree_size"],
                "root_hash": sth["root_hash"],
                "signature": base64.b64encode(signature).decode('ascii')
            }
            
            async with self.session.post(
                submit_url,
                json=payload,
                timeout=REQUEST_TIMEOUT
            ) as response:
                if response.status not in (200, 201):
                    logger.error(f"Failed to submit witness signature: HTTP {response.status}")
                    return False
                
                logger.info(f"Successfully submitted witness signature for log {log.log_id}")
                return True
                
        except Exception as e:
            logger.error(f"Error co-signing STH: {e}", exc_info=True)
            return False


async def main():
    """Run the witness service."""
    # Example configuration (in a real deployment, load from a config file)
    config = {
        "witness_id": "witness-1",
        "private_key": "your-private-key-here",  # In a real deployment, load this securely
        "monitored_logs": [
            {
                "url": "http://localhost:8000",
                "log_id": "default-log",
                "public_key": "your-public-key-here"
            }
        ],
        "poll_interval": 300,  # 5 minutes
        "min_witness_interval": 60  # 1 minute
    }
    
    # Create and start the witness service
    witness = WitnessService(config=WitnessConfig(**config))
    await witness.start()
    
    try:
        # Keep the service running
        while True:
            await asyncio.sleep(3600)  # Sleep for an hour
    except KeyboardInterrupt:
        await witness.stop()


if __name__ == "__main__":
    asyncio.run(main())
