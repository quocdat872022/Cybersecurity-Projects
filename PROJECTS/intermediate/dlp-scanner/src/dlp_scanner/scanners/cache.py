import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import List, Optional, Dict, Any

from dlp_scanner.models import ScanResult
from dlp_scanner.config import ScanConfig
from dlp_scanner.detectors.registry import DetectorRegistry
from dlp_scanner.models import Finding


class ScanCache:
    """
    Persistent cache for DLP scan results using file content hashing + config fingerprinting.
    """

    def __init__(self, cache_db_path: Path):
        self.db_path = cache_db_path
        self.conn = sqlite3.connect(str(cache_db_path))
        self._init_db()

    def _init_db(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_cache (
                file_path TEXT PRIMARY KEY,
                content_hash TEXT NOT NULL,
                config_hash TEXT NOT NULL,
                scan_time TEXT NOT NULL,
                finding_count INTEGER NOT NULL,
                findings_json TEXT NOT NULL
            )
        """)
        self.conn.commit()

    def _compute_file_hash(self, file_path: Path) -> str:
        """SHA-256 of file content"""
        sha = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha.update(chunk)
        return sha.hexdigest()

    def _compute_config_hash(self, config: ScanConfig, registry: DetectorRegistry) -> str:
        """Hash of detection rules + important config settings"""
        # Safer fingerprinting - avoid assuming internal structure
        detector_fingerprints = []

        # Try different possible structures safely
        try:
            # Common patterns for rule registries
            if hasattr(registry, '_pattern_detector') and hasattr(registry._pattern_detector, '_rules'):
                rules = registry._pattern_detector._rules
                
                for rule in rules:
                    name = getattr(rule, 'rule_name', str(rule))
                    rule_id = getattr(rule, 'rule_id', str(rule))
                    detector_fingerprints.append(f"{name}:{rule_id}")

        except Exception:
            # Fallback: just use number of enabled rules
            detector_fingerprints.append(f"rule_count:{len(getattr(registry, 'enabled_rules', []))}")

        state = {
            "min_confidence": getattr(config.detection, 'min_confidence', 0.0),
            "detectors": sorted(detector_fingerprints),
            "redaction_style": getattr(config.output, 'redaction_style', 'mask'),
            "enabled_rules": getattr(config.detection, 'enable_rules', []),
            "disabled_rules": getattr(config.detection, 'disable_rules', []),
        }
        return hashlib.sha256(
            json.dumps(state, sort_keys=True).encode()
        ).hexdigest()

    def get_cached_findings(
        self, 
        file_path: Path, 
        config: ScanConfig, 
        registry: DetectorRegistry
    ) -> Optional[List[Finding]]:
        """Return cached findings if file and config are unchanged"""
        if not file_path.exists():
            return None

        content_hash = self._compute_file_hash(file_path)
        config_hash = self._compute_config_hash(config, registry)

        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT findings_json, content_hash, config_hash 
            FROM scan_cache 
            WHERE file_path = ?
        """, (str(file_path.absolute()),))

        row = cursor.fetchone()
        if row:
            findings_json, cached_content_hash, cached_config_hash = row
            if cached_content_hash == content_hash and cached_config_hash == config_hash:
                return json.loads(findings_json)

        return None

    def save_findings(
        self, 
        file_path: Path, 
        findings: List[Any | Dict [str, Any]], 
        config: ScanConfig, 
        registry: DetectorRegistry
    ):
        """Save findings to cache"""
        if not file_path.exists():
            return

        content_hash = self._compute_file_hash(file_path)
        config_hash = self._compute_config_hash(config, registry)
        scan_time = time.strftime("%Y-%m-%d %H:%M:%S")

        # Convert findings to serializable dicts
        findings_dicts = []
        for f in findings:
            if hasattr(f, 'model_dump'):
                findings_dicts.append(f.model_dump())
            elif hasattr(f, '__dict__'):
                findings_dicts.append(vars(f))
            else:
                findings_dicts.append(str(f))

        self.conn.execute("""
            INSERT OR REPLACE INTO scan_cache 
            (file_path, content_hash, config_hash, scan_time, finding_count, findings_json)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            str(file_path.absolute()),
            content_hash,
            config_hash,
            scan_time,
            len(findings),
            json.dumps(findings_dicts, default=str)
        ))
        self.conn.commit()

    def invalidate(self):
        """Clear entire cache (e.g. after major config changes)"""
        self.conn.execute("DELETE FROM scan_cache")
        self.conn.commit()

    def cleanup_deleted(self, scanned_paths: set[str]):
        """Remove stale entries for deleted files"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT file_path FROM scan_cache")
        for (fp,) in cursor.fetchall():
            if fp not in scanned_paths:
                self.conn.execute("DELETE FROM scan_cache WHERE file_path = ?", (fp,))
        self.conn.commit()

    def close(self):
        if self.conn:
            self.conn.close()