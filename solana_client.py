"""
AtenLana Solana Client
Handles SPL token minting, Compressed NFT badges, and on-chain attendance proofs
via Helius API (no Solana CLI or Rust needed).
"""

import os
import hashlib
import json
import time
import logging
from datetime import datetime, timezone

import requests

logger = logging.getLogger(__name__)

HELIUS_API_KEY = os.environ.get('HELIUS_API_KEY', '')
HELIUS_BASE = 'https://api.helius.xyz/v0'
HELIUS_RPC = f'https://mainnet.helius.xyz/?api-key={HELIUS_API_KEY}'

# Default $ATND token mint address — created via Helius token setup
# Students receive this token when they mark attendance
ATND_TOKEN_MINT = os.environ.get('ATND_TOKEN_MINT', '')

# Collection mint for cNFT badges (created once via Helius)
BADGE_COLLECTION_MINT = os.environ.get('BADGE_COLLECTION_MINT', '')

FEE_PAYER = os.environ.get('SOLANA_FEE_PAYER', '')


def is_configured():
    return bool(HELIUS_API_KEY) and bool(FEE_PAYER)


def _headers():
    return {
        'Content-Type': 'application/json',
        'x-api-key': HELIUS_API_KEY
    }


def create_token_metadata(name, symbol, uri, mint_authority=None):
    """Create SPL token metadata (run once to set up $ATND token)."""
    if not is_configured():
        logger.info("Solana not configured — skipping token creation")
        return None
    payload = {
        "jsonrpc": "2.0",
        "id": "atenlana-create-token",
        "method": "createTokenMetadata",
        "params": {
            "metadata": {
                "name": name,
                "symbol": symbol,
                "uri": uri,
                "sellerFeeBasisPoints": 0,
            },
            "mintAuthority": mint_authority or FEE_PAYER,
            "payer": FEE_PAYER,
        }
    }
    try:
        resp = requests.post(HELIUS_RPC, json=payload, timeout=30)
        data = resp.json()
        if 'result' in data:
            mint = data['result']['mint']
            logger.info(f"Token created: {mint}")
            return mint
        logger.error(f"Token creation failed: {data}")
        return None
    except Exception as e:
        logger.error(f"Token creation error: {e}")
        return None


def mint_token(wallet_address, amount=10):
    """Mint $ATND SPL tokens to a student's wallet."""
    if not is_configured() or not ATND_TOKEN_MINT:
        logger.info(f"Solana not configured — skipping token mint to {wallet_address}")
        return False
    payload = {
        "jsonrpc": "2.0",
        "id": "atenlana-mint",
        "method": "mintToken",
        "params": {
            "mint": ATND_TOKEN_MINT,
            "destination": wallet_address,
            "amount": amount,
            "payer": FEE_PAYER,
        }
    }
    try:
        resp = requests.post(HELIUS_RPC, json=payload, timeout=30)
        data = resp.json()
        if 'result' in data:
            logger.info(f"Minted {amount} $ATND to {wallet_address}: {data['result']}")
            return True
        logger.warning(f"Token mint failed: {data}")
        return False
    except Exception as e:
        logger.error(f"Token mint error: {e}")
        return False


def mint_badge(wallet_address, tier):
    """Mint a Compressed NFT badge for attendance milestones."""
    if not is_configured():
        logger.info(f"Solana not configured — skipping badge mint for {wallet_address}")
        return False

    tier_config = {
        'bronze': {'name': 'AtenLana Bronze Attendant', 'description': 'Attended 10 classes', 'color': '#cd7f32'},
        'silver': {'name': 'AtenLana Silver Attendant', 'description': 'Attended 25 classes', 'color': '#c0c0c0'},
        'gold': {'name': 'AtenLana Gold Attendant', 'description': 'Attended 50 classes', 'color': '#ffd700'},
        'diamond': {'name': 'AtenLana Diamond Attendant', 'description': 'Attended 100 classes', 'color': '#b9f2ff'},
    }
    cfg = tier_config.get(tier, tier_config['bronze'])
    ts = int(time.time())

    metadata = {
        "name": cfg['name'],
        "symbol": "ATND",
        "description": cfg['description'],
        "image": f"https://atenlana.vercel.app/static/badges/{tier}.png",
        "attributes": [
            {"trait_type": "Tier", "value": tier.capitalize()},
            {"trait_type": "Attendances", "value": str({
                'bronze': 10, 'silver': 25, 'gold': 50, 'diamond': 100
            }.get(tier, 0))},
            {"trait_type": "Issued", "value": datetime.now(timezone.utc).strftime('%Y-%m-%d')},
        ]
    }

    payload = {
        "jsonrpc": "2.0",
        "id": "atenlana-badge",
        "method": "mintCompressedNft",
        "params": {
            "collectionMint": BADGE_COLLECTION_MINT,
            "metadata": metadata,
            "recipient": wallet_address,
            "payer": FEE_PAYER,
        }
    }
    try:
        resp = requests.post(HELIUS_RPC, json=payload, timeout=30)
        data = resp.json()
        if 'result' in data:
            sig = data['result']['signature'] if isinstance(data['result'], dict) else data['result']
            logger.info(f"Badge minted for {wallet_address}: {sig}")
            return True
        logger.warning(f"Badge mint failed: {data}")
        return False
    except Exception as e:
        logger.error(f"Badge mint error: {e}")
        return False


def record_attendance(student_id, session_id, timestamp, wallet_address=None):
    """Record a SHA256 hash of attendance on Solana as an immutable proof."""
    if not is_configured():
        logger.info("Solana not configured — skipping on-chain record")
        return None

    hash_input = f"{student_id}|{session_id}|{timestamp}|ATENLANA"
    hash_hex = hashlib.sha256(hash_input.encode()).hexdigest()

    memo = f"ATENLANA:ATTENDANCE:{hash_hex}"

    payload = {
        "jsonrpc": "2.0",
        "id": "atenlana-record",
        "method": "sendTransaction",
        "params": {
            "instructions": [
                {
                    "programId": "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
                    "data": memo,
                }
            ],
            "payer": FEE_PAYER,
            "signers": [FEE_PAYER],
        }
    }
    try:
        resp = requests.post(HELIUS_RPC, json=payload, timeout=30)
        data = resp.json()
        if 'result' in data:
            sig = data['result'] if isinstance(data['result'], str) else data['result'].get('signature', '')
            logger.info(f"Attendance recorded on-chain: {sig}")
            return sig
        logger.warning(f"On-chain record failed: {data}")
        return None
    except Exception as e:
        logger.error(f"On-chain record error: {e}")
        return None


def get_assets(wallet_address):
    """Fetch all tokens and NFTs for a wallet (to display on dashboard)."""
    if not is_configured():
        return {'tokens': [], 'nfts': []}
    try:
        resp = requests.get(
            f"{HELIUS_BASE}/addresses/{wallet_address}/assets",
            headers={'x-api-key': HELIUS_API_KEY},
            timeout=15
        )
        data = resp.json()
        items = data.get('items', []) if isinstance(data, dict) else []
        tokens = [i for i in items if i.get('type') == 'fungible']
        nfts = [i for i in items if i.get('type') == 'compressed_nft']
        return {'tokens': tokens, 'nfts': nfts}
    except Exception as e:
        logger.error(f"Get assets error: {e}")
        return {'tokens': [], 'nfts': []}
