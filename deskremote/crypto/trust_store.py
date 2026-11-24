"""Trust-On-First-Use (TOFU) peer Ed25519 identity store."""

from __future__ import annotations

import datetime
import json
import os
import threading
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from deskremote.config import CONFIG_DIR, TRUST_STORE_FILE


class TrustStatus(str, Enum):
    TRUSTED = "trusted"          # Known device with matching Ed25519 key
    NEW = "new"                  # First time seeing this device
    KEY_CHANGED = "key_changed"  # WARNING: Known peer name but DIFFERENT Ed25519 key!


@dataclass
class PeerRecord:
    peer_name: str
    fingerprint: str
    public_key_hex: str
    first_seen: str
    last_seen: str

    def to_dict(self) -> dict[str, str]:
        return {
            "peer_name": self.peer_name,
            "fingerprint": self.fingerprint,
            "public_key_hex": self.public_key_hex,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "PeerRecord":
        return cls(
            peer_name=str(data.get("peer_name", "")),
            fingerprint=str(data.get("fingerprint", "")),
            public_key_hex=str(data.get("public_key_hex", "")),
            first_seen=str(data.get("first_seen", "")),
            last_seen=str(data.get("last_seen", "")),
        )


@dataclass
class TrustEvaluation:
    status: TrustStatus
    existing_record: PeerRecord | None = None


class TrustStore:
    """Thread-safe persistent TOFU store for verified peer Ed25519 public keys."""

    def __init__(self, path: Path = TRUST_STORE_FILE) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._records: dict[str, PeerRecord] = {}  # keyed by fingerprint
        self._load()

    def _load(self) -> None:
        try:
            if self.path.exists():
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(raw, list):
                    for item in raw:
                        rec = PeerRecord.from_dict(item)
                        if rec.fingerprint and rec.public_key_hex:
                            self._records[rec.fingerprint] = rec
        except (OSError, json.JSONDecodeError):
            self._records = {}

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            data = [r.to_dict() for r in self._records.values()]
            self.path.write_text(
                json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            if os.name != "nt":
                os.chmod(self.path, 0o600)
        except OSError:
            pass

    def evaluate(
        self, peer_name: str, fingerprint: str, public_key_bytes: bytes
    ) -> TrustEvaluation:
        """Evaluate whether a connecting peer is TRUSTED, NEW, or KEY_CHANGED."""
        pub_hex = public_key_bytes.hex()
        with self._lock:
            # 1. Exact cryptographic key match (even if peer renamed their PC)
            rec = self._records.get(fingerprint)
            if rec is not None and rec.public_key_hex == pub_hex:
                return TrustEvaluation(TrustStatus.TRUSTED, rec)

            # 2. Same peer hostname already trusted under a DIFFERENT Ed25519 key -> WARNING!
            name_norm = peer_name.strip().lower()
            if name_norm:
                for existing in self._records.values():
                    if (
                        existing.peer_name.strip().lower() == name_norm
                        and existing.public_key_hex != pub_hex
                    ):
                        return TrustEvaluation(TrustStatus.KEY_CHANGED, existing)

            return TrustEvaluation(TrustStatus.NEW, None)

    def trust_peer(
        self, peer_name: str, fingerprint: str, public_key_bytes: bytes
    ) -> PeerRecord:
        """Save or update a peer's Ed25519 identity in the TOFU store."""
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        pub_hex = public_key_bytes.hex()
        with self._lock:
            existing = self._records.get(fingerprint)
            # If user explicitly approves a KEY_CHANGED peer, replace old record with same name
            name_norm = peer_name.strip().lower()
            stale_fps = [
                fp
                for fp, r in self._records.items()
                if fp != fingerprint and r.peer_name.strip().lower() == name_norm
            ]
            for fp in stale_fps:
                del self._records[fp]

            rec = PeerRecord(
                peer_name=peer_name,
                fingerprint=fingerprint,
                public_key_hex=pub_hex,
                first_seen=existing.first_seen if existing else now,
                last_seen=now,
            )
            self._records[fingerprint] = rec
            self._save()
            return rec

    def touch_peer(self, fingerprint: str) -> None:
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        with self._lock:
            rec = self._records.get(fingerprint)
            if rec is not None:
                rec.last_seen = now
                self._save()

    def revoke_peer(self, fingerprint: str) -> bool:
        with self._lock:
            if fingerprint in self._records:
                del self._records[fingerprint]
                self._save()
                return True
            return False

    def list_peers(self) -> list[PeerRecord]:
        with self._lock:
            return sorted(
                self._records.values(), key=lambda r: r.last_seen, reverse=True
            )
