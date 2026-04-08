#!/usr/bin/env python3
"""
ForensiX Studio - Professional Forensic Analysis Tool
Version 3.1 - Industry‑Grade Forensic Decision Engine
"""

import sys
import os
import stat
import mimetypes
import math
import datetime
import base64
import hashlib
import csv
import json
import zipfile
import sqlite3
import difflib
import random
import string
import shutil
import struct
import logging
import tempfile
import platform
import subprocess
import hmac
import re
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Set, Any, Union
from collections import defaultdict

# PySide6
from PySide6 import QtCore, QtGui, QtWidgets
from PySide6.QtCore import QThread, Signal

# Crypto
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# Optional libs – degrade gracefully if missing
try:
    from PIL import Image, ExifTags
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    from pypdf import PdfReader, PdfWriter
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False

try:
    from mutagen import File as MutagenFile
    MUTAGEN_AVAILABLE = True
except ImportError:
    MUTAGEN_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("ForensiX")

APP_TITLE = "ForensiX Studio Pro"
ENC_MAGIC = b"FXENC1"
STEG_MAGIC = b"FXSTEG1"
PBKDF2_ITERATIONS = 600_000
STATE_FILE = os.path.join(os.path.expanduser("~"), ".forensix_studio_state.json")
CHUNK_SIZE = 64 * 1024


# ------------------------ Utility Helpers ------------------------
def human_size(num_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(num_bytes)
    for unit in units:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def file_times(path: str, mode: str = "local"):
    st = os.stat(path)

    def fmt(ts):
        if mode == "utc":
            dt = datetime.datetime.utcfromtimestamp(ts)
        else:
            dt = datetime.datetime.fromtimestamp(ts)
        return dt.strftime("%Y-%m-%d %H:%M:%S"), dt

    c_str, c_dt = fmt(st.st_ctime)
    m_str, m_dt = fmt(st.st_mtime)
    a_str, a_dt = fmt(st.st_atime)
    return (c_str, c_dt), (m_str, m_dt), (a_str, a_dt)


def file_permissions(path: str) -> str:
    mode = os.stat(path).st_mode
    parts = []
    parts.append("r" if mode & stat.S_IRUSR else "-")
    parts.append("w" if mode & stat.S_IWUSR else "-")
    parts.append("x" if mode & stat.S_IXUSR else "-")
    parts.append(" | ")
    parts.append("r" if mode & stat.S_IRGRP else "-")
    parts.append("w" if mode & stat.S_IWGRP else "-")
    parts.append("x" if mode & stat.S_IXGRP else "-")
    parts.append(" | ")
    parts.append("r" if mode & stat.S_IROTH else "-")
    parts.append("w" if mode & stat.S_IWOTH else "-")
    parts.append("x" if mode & stat.S_IXOTH else "-")
    return "".join(parts)


def compute_hashes(path: str, algo_list=None):
    if algo_list is None:
        algo_list = ["md5", "sha1", "sha256", "sha512"]
    hash_objs = {name: getattr(hashlib, name)() for name in algo_list}
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            for h in hash_objs.values():
                h.update(chunk)
    return {name: h.hexdigest() for name, h in hash_objs.items()}


def estimate_entropy(path: str, max_bytes: int = 1024 * 1024) -> float:
    size = os.path.getsize(path)
    n = min(size, max_bytes)
    if n == 0:
        return 0.0
    with open(path, "rb") as f:
        data = f.read(n)
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy


def file_magic(path: str, length: int = 8) -> bytes:
    with open(path, "rb") as f:
        return f.read(length)


MAGIC_KNOWN = {
    b"%PDF": "PDF document",
    b"\x89PNG\r\n\x1a\n": "PNG image",
    b"\xff\xd8\xff": "JPEG image",
    b"PK\x03\x04": "ZIP / DOCX / JAR / APK",
    b"Rar!\x1a\x07\x00": "RAR archive",
    b"7z\xbc\xaf\x27\x1c": "7z archive",
    b"MZ": "Windows PE executable",
    b"GIF87a": "GIF image",
    b"GIF89a": "GIF image",
}


def detect_magic_label(magic: bytes) -> str:
    for sig, label in MAGIC_KNOWN.items():
        if magic.startswith(sig):
            return label
    return "Unknown / not in signature list"


def chromium_time_to_str(value: int) -> str:
    if not value or value <= 0:
        return ""
    try:
        epoch_start = datetime.datetime(1601, 1, 1)
        dt = epoch_start + datetime.timedelta(microseconds=value)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""


# ------------------------ Cryptographic Helpers (AES-256-GCM) ------------------------
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file_streaming(src_path: str, dst_path: str, password: str):
    salt = os.urandom(32)
    key = derive_key(password, salt)
    iv = os.urandom(12)
    aesgcm = AESGCM(key)

    with open(src_path, "rb") as f_in, open(dst_path, "wb") as f_out:
        f_out.write(ENC_MAGIC)
        f_out.write(salt)
        f_out.write(iv)
        data = f_in.read()
        ciphertext = aesgcm.encrypt(iv, data, None)
        f_out.write(ciphertext)


def decrypt_file_streaming(src_path: str, dst_path: str, password: str):
    with open(src_path, "rb") as f_in:
        magic = f_in.read(len(ENC_MAGIC))
        if magic != ENC_MAGIC:
            raise ValueError("Not a ForensiX Studio encrypted file (wrong magic).")
        salt = f_in.read(32)
        iv = f_in.read(12)
        ciphertext = f_in.read()

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(iv, ciphertext, None)
    except InvalidTag:
        raise ValueError("Wrong password or corrupted encrypted file.")

    with open(dst_path, "wb") as f_out:
        f_out.write(plaintext)


# ------------------------ Secure Wipe ------------------------
def secure_wipe_file(path: str, passes: int = 3) -> bool:
    if not os.path.exists(path):
        return False

    if platform.system() != "Windows":
        try:
            subprocess.run(["shred", "-f", "-z", f"-n{passes}", path], check=True, capture_output=True)
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.warning("shred not available, falling back to manual overwrite")

    try:
        size = os.path.getsize(path)
        with open(path, "wb") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
            f.seek(0)
            f.write(b"\x00" * size)
            f.flush()
            os.fsync(f.fileno())
        os.remove(path)
        return True
    except Exception as e:
        logger.error(f"Secure wipe failed: {e}")
        return False


# ------------------------ Steganography (Chunked) ------------------------
class SteganographyHelper:
    @staticmethod
    def embed_text(image_path: str, output_path: str, text: str) -> bool:
        if not PIL_AVAILABLE:
            return False
        try:
            img = Image.open(image_path).convert("RGB")
            b_text = text.encode("utf-8")
            if len(b_text) > 1_000_000:
                raise ValueError("Text too long.")
            length_bytes = struct.pack(">I", len(b_text))
            payload = length_bytes + b_text + b"FXEND"
            bits = []
            for byte in payload:
                for i in range(8):
                    bits.append((byte >> (7 - i)) & 1)

            pixels = list(img.getdata())
            if len(bits) > len(pixels) * 3:
                raise ValueError("Image too small.")

            new_pixels = []
            bit_idx = 0
            for r, g, b in pixels:
                if bit_idx < len(bits):
                    r = (r & ~1) | bits[bit_idx]
                    bit_idx += 1
                if bit_idx < len(bits):
                    g = (g & ~1) | bits[bit_idx]
                    bit_idx += 1
                if bit_idx < len(bits):
                    b = (b & ~1) | bits[bit_idx]
                    bit_idx += 1
                new_pixels.append((r, g, b))

            new_img = Image.new("RGB", img.size)
            new_img.putdata(new_pixels)
            new_img.save(output_path, "PNG")
            return True
        except Exception as e:
            logger.error(f"Stego embed failed: {e}")
            return False

    @staticmethod
    def extract_text(image_path: str) -> Optional[str]:
        if not PIL_AVAILABLE:
            return None
        try:
            img = Image.open(image_path).convert("RGB")
            pixels = list(img.getdata())

            def bit_gen():
                for r, g, b in pixels:
                    yield r & 1
                    yield g & 1
                    yield b & 1

            bg = bit_gen()
            len_bits = [next(bg) for _ in range(32)]
            length_val = 0
            for b in len_bits:
                length_val = (length_val << 1) | b
            if length_val <= 0 or length_val > 10_000_000:
                return None
            payload_bits = [next(bg) for _ in range(length_val * 8)]
            payload_bytes = bytearray()
            for i in range(0, len(payload_bits), 8):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | payload_bits[i + j]
                payload_bytes.append(byte)
            if payload_bytes[-5:] != b"FXEND":
                return None
            return payload_bytes[:-5].decode("utf-8", errors="ignore")
        except Exception as e:
            logger.error(f"Stego extract failed: {e}")
            return None


# ------------------------ Malware Scorer ------------------------
class MalwareScorer:
    @staticmethod
    def score_file(path: str, entropy: float, magic_desc: str, bad_hashes: set) -> dict:
        score = 0
        reasons = []
        is_pe = "Windows PE" in magic_desc
        if entropy > 7.2:
            score += 40
            reasons.append("Very high entropy (>7.2)")
        elif entropy > 6.8:
            score += 20
            reasons.append("High entropy (>6.8)")
        h = compute_hashes(path, ["sha256"])["sha256"]
        if h in bad_hashes:
            score = 100
            reasons.insert(0, "MATCHES KNOWN BAD HASH")
        base = os.path.basename(path).lower()
        if base.endswith((".exe", ".dll", ".scr", ".vbs", ".ps1", ".bat")):
            score += 10
            reasons.append("Executable/Script extension")
        if is_pe and PEFILE_AVAILABLE:
            try:
                pe = pefile.PE(path)
                suspicious_sections = 0
                for sect in pe.sections:
                    if sect.get_entropy() > 7.4:
                        suspicious_sections += 1
                if suspicious_sections > 0:
                    score += 20 * suspicious_sections
                    reasons.append(f"{suspicious_sections} high-entropy PE sections")
                if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                    if len(pe.DIRECTORY_ENTRY_IMPORT) < 3:
                        score += 20
                        reasons.append("Very few imports (possible packer)")
            except Exception:
                pass
        score = min(100, score)
        return {"score": score, "reasons": reasons, "hash": h}


# ------------------------ IOC Extractor Base ------------------------
class IOCExtractor:
    IPV4_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    URL_PATTERN = re.compile(r'\bhttps?://[^\s<>"\'{}|\\^`\[\]]+', re.IGNORECASE)
    DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
    EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

    @staticmethod
    def extract_from_bytes(data: bytes) -> Dict[str, List[str]]:
        try:
            text = data.decode('latin-1')
        except:
            text = data.decode('utf-8', errors='ignore')
        return IOCExtractor.extract_from_text(text)

    @staticmethod
    def extract_from_text(text: str) -> Dict[str, List[str]]:
        ips = set(IOCExtractor.IPV4_PATTERN.findall(text))
        urls = set(IOCExtractor.URL_PATTERN.findall(text))
        domains = set(IOCExtractor.DOMAIN_PATTERN.findall(text))
        emails = set(IOCExtractor.EMAIL_PATTERN.findall(text))
        filtered_domains = set()
        for d in domains:
            if not any(d in url for url in urls) and not any(d in email for email in emails):
                filtered_domains.add(d)
        return {
            'ips': sorted(ips),
            'urls': sorted(urls),
            'domains': sorted(filtered_domains),
            'emails': sorted(emails),
        }


# ------------------------ Enhanced IOC Extractor ------------------------
class EnhancedIOCExtractor(IOCExtractor):
    @classmethod
    def extract_with_classification(cls, data: bytes, file_size: int) -> Dict[str, Any]:
        text = data.decode('latin-1')
        iocs = cls.extract_from_text(text)

        internal_ips = []
        external_ips = []
        for ip in iocs['ips']:
            if cls._is_private_ip(ip):
                internal_ips.append(ip)
            else:
                external_ips.append(ip)

        suspicious_domains = []
        normal_domains = []
        suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work'}
        for domain in iocs['domains']:
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                suspicious_domains.append(domain)
            else:
                normal_domains.append(domain)

        iocs['_file_size_mb'] = file_size / (1024 * 1024)
        iocs['internal_ips'] = internal_ips
        iocs['external_ips'] = external_ips
        iocs['suspicious_domains'] = suspicious_domains
        iocs['normal_domains'] = normal_domains
        iocs['total_iocs'] = sum(len(v) for k, v in iocs.items() if isinstance(v, list))

        return iocs

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        try:
            parts = [int(p) for p in ip.split('.')]
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            if parts[0] == 127:
                return True
            return False
        except:
            return False


# ------------------------ File Mismatch Detector ------------------------
class FileMismatchDetector:
    EXT_MAGIC_MAP = {
        '.png': [b'\x89PNG'],
        '.jpg': [b'\xff\xd8\xff'],
        '.jpeg': [b'\xff\xd8\xff'],
        '.gif': [b'GIF87a', b'GIF89a'],
        '.pdf': [b'%PDF'],
        '.zip': [b'PK\x03\x04'],
        '.docx': [b'PK\x03\x04'],
        '.xlsx': [b'PK\x03\x04'],
        '.exe': [b'MZ'],
        '.dll': [b'MZ'],
        '.elf': [b'\x7fELF'],
        '.macho': [b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe'],
        '.rar': [b'Rar!\x1a\x07\x00'],
        '.7z': [b"7z\xbc\xaf'\x1c"],
        '.txt': [],
    }

    @classmethod
    def detect(cls, path: str, mime_type: str = None) -> Dict[str, Any]:
        ext = os.path.splitext(path)[1].lower()
        magic = file_magic(path, 8)
        magic_desc = detect_magic_label(magic)

        result = {
            'is_mismatch': False,
            'explanation': '',
            'expected_type': '',
            'actual_type': magic_desc,
            'extension': ext
        }

        expected_magics = cls.EXT_MAGIC_MAP.get(ext, [])
        if expected_magics:
            if not any(magic.startswith(sig) for sig in expected_magics):
                result['is_mismatch'] = True
                expected = cls._describe_expected(ext)
                result['expected_type'] = expected
                result['explanation'] = f"Extension '{ext}' suggests {expected} but magic bytes indicate '{magic_desc}'"
        elif ext and ext not in ['.txt', '.log', '.csv', '.json', '.xml', '.html']:
            if cls._is_text_file(path) and magic_desc == 'Unknown / not in signature list':
                pass
            elif magic_desc != 'Unknown / not in signature list':
                result['is_mismatch'] = True
                result['explanation'] = f"File with extension '{ext}' has unexpected magic: '{magic_desc}'"

        if mime_type:
            expected_mime_category = mime_type.split('/')[0]
            if expected_mime_category == 'image' and 'image' not in magic_desc.lower():
                result['is_mismatch'] = True
                result['explanation'] = f"MIME type '{mime_type}' conflicts with magic '{magic_desc}'"
            elif expected_mime_category == 'text' and magic_desc not in ('Unknown', 'ASCII'):
                if b'<?php' in magic or b'#!/' in magic:
                    pass
                elif magic_desc not in ('Unknown', 'ASCII text'):
                    result['is_mismatch'] = True
                    result['explanation'] = f"Text MIME type but magic shows '{magic_desc}'"

        return result

    @staticmethod
    def _describe_expected(ext: str) -> str:
        mapping = {
            '.png': 'PNG image',
            '.jpg': 'JPEG image',
            '.jpeg': 'JPEG image',
            '.gif': 'GIF image',
            '.pdf': 'PDF document',
            '.zip': 'ZIP archive',
            '.docx': 'Word document',
            '.xlsx': 'Excel spreadsheet',
            '.exe': 'Windows executable',
            '.dll': 'Windows DLL',
            '.elf': 'Linux executable',
            '.macho': 'macOS executable',
        }
        return mapping.get(ext, ext)

    @staticmethod
    def _is_text_file(path: str, sample_size: int = 1024) -> bool:
        try:
            with open(path, 'rb') as f:
                data = f.read(sample_size)
            null_count = data.count(b'\x00')
            if null_count > 0:
                return False
            printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in data)
            return printable / len(data) > 0.9
        except:
            return False


# ------------------------ Suspicious String Analyzer ------------------------
class SuspiciousStringAnalyzer:
    KEYWORD_WEIGHTS = {
        'password': 4, 'passwd': 4, 'pwd': 3, 'pass': 3,
        'token': 4, 'api_key': 5, 'apikey': 5, 'secret': 4,
        'auth': 3, 'bearer': 3, 'credential': 4, 'private key': 5,
        '-----BEGIN': 4, '-----END': 4,
        'admin': 2, 'administrator': 2, 'root': 2,
        'eval': 4, 'exec': 4, 'system': 3, 'shell': 4,
        'cmd.exe': 4, 'powershell': 4, 'wscript': 4, 'cscript': 4,
        'http://': 2, 'https://': 2, '.onion': 3,
        'bitcoin': 3, 'wallet': 3, 'cryptocurrency': 2,
        'ransom': 5, 'decrypt': 4, 'encrypt': 3,
    }

    @classmethod
    def analyze(cls, strings: List[str]) -> List[Dict[str, Any]]:
        suspicious = []
        for s in strings:
            s_lower = s.lower()
            severity = 0
            reasons = []
            s_type = 'keyword'

            for kw, weight in cls.KEYWORD_WEIGHTS.items():
                if kw in s_lower:
                    severity = max(severity, weight)
                    reasons.append(f"contains '{kw}'")

            if cls._looks_like_base64(s):
                severity = max(severity, 3)
                reasons.append("possible base64 encoded data")
                s_type = 'base64'

            if len(s) > 20 and cls._string_entropy(s) > 4.0:
                severity = max(severity, 4)
                reasons.append("high entropy (possible key/token)")
                s_type = 'high_entropy'

            if cls._is_credential_pattern(s):
                severity = max(severity, 4)
                reasons.append("credential pattern")
                s_type = 'credential'

            if severity >= 2:
                suspicious.append({
                    'string': s,
                    'severity': severity,
                    'reason': ', '.join(reasons),
                    'type': s_type
                })

        suspicious.sort(key=lambda x: x['severity'], reverse=True)
        return suspicious

    @staticmethod
    def _looks_like_base64(s: str) -> bool:
        if len(s) < 20:
            return False
        b64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        if any(c not in b64_chars for c in s):
            return False
        if s.count('=') > len(s) * 0.1:
            return False
        ratio = sum(1 for c in s if c in b64_chars) / len(s)
        return ratio > 0.9 and len(s) % 4 == 0

    @staticmethod
    def _string_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = {}
        for ch in s:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(s)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _is_credential_pattern(s: str) -> bool:
        s_lower = s.lower()
        if ':' in s or '=' in s:
            parts = re.split('[:=]', s)
            if len(parts) >= 2:
                key_part = parts[0].strip().lower()
                if any(k in key_part for k in ['user', 'username', 'login', 'email', 'key', 'token', 'pass', 'pwd']):
                    return True
        return False


# ------------------------ Analysis Engine ------------------------
class AnalysisEngine:
    WEIGHTS = {
        'entropy': 0.15,
        'malware_score': 0.25,
        'threat_intel': 0.20,
        'ioc_presence': 0.15,
        'suspicious_strings': 0.10,
        'file_mismatch': 0.10,
        'executable_flags': 0.05,
    }

    @classmethod
    def analyze(cls, results: Dict[str, Any]) -> Dict[str, Any]:
        risk_score = 0.0
        findings = []
        explanation_parts = []
        
        # Breakdown components
        breakdown = {}

        # 1. Entropy
        entropy = results.get('entropy', 0.0)
        entropy_risk, entropy_findings = cls._analyze_entropy(entropy)
        contrib = entropy_risk * cls.WEIGHTS['entropy']
        risk_score += contrib
        breakdown['entropy'] = round(contrib * 100, 1)
        findings.extend(entropy_findings)
        explanation_parts.extend(entropy_findings)

        # 2. Malware Score
        malware_score = results.get('malware_score', 0)
        malware_risk = malware_score / 100.0
        contrib = malware_risk * cls.WEIGHTS['malware_score']
        risk_score += contrib
        breakdown['malware_heuristics'] = round(contrib * 100, 1)
        if malware_score >= 70:
            findings.append(f"Critical malware score: {malware_score}/100")
            explanation_parts.append(f"Critical heuristic score ({malware_score})")

        # 3. Threat Intelligence
        intel = results.get('threat_intel', {})
        intel_verdict = intel.get('verdict', 'unknown')
        intel_risk = 0.0
        if intel_verdict == 'malicious': intel_risk = 1.0
        elif intel_verdict == 'suspicious': intel_risk = 0.5
        elif intel.get('detections', 0) > 0:
            intel_risk = min(1.0, (intel['detections'] / 10.0))
        
        contrib = intel_risk * cls.WEIGHTS['threat_intel']
        risk_score += contrib
        breakdown['threat_intel'] = round(contrib * 100, 1)
        if intel_risk > 0:
            findings.append(f"External Intelligence: {intel.get('detections', 0)} engines flagged this hash")
            explanation_parts.append(f"Threat intelligence match ({intel.get('detections', 0)} detections)")

        # 4. IOCs
        iocs = results.get('iocs', {})
        ioc_risk, ioc_findings = cls._analyze_iocs(iocs)
        contrib = ioc_risk * cls.WEIGHTS['ioc_presence']
        risk_score += contrib
        breakdown['indicators'] = round(contrib * 100, 1)
        findings.extend(ioc_findings)
        explanation_parts.extend(ioc_findings)

        # 5. Suspicious Strings
        susp_strings = results.get('suspicious_strings', [])
        string_risk, string_findings = cls._analyze_suspicious_strings(susp_strings)
        contrib = string_risk * cls.WEIGHTS['suspicious_strings']
        risk_score += contrib
        breakdown['strings'] = round(contrib * 100, 1)
        findings.extend(string_findings)
        explanation_parts.extend(string_findings)

        # 6. File Mismatch
        mismatch_info = results.get('file_mismatch', {})
        mismatch_risk = 1.0 if mismatch_info.get('is_mismatch') else 0.0
        contrib = mismatch_risk * cls.WEIGHTS['file_mismatch']
        risk_score += contrib
        breakdown['mismatch'] = round(contrib * 100, 1)
        if mismatch_risk > 0:
            msg = f"File type mismatch: {mismatch_info.get('explanation', '')}"
            findings.append(msg)
            explanation_parts.append(msg)

        # 7. Executable Flags
        pe_indicators = results.get('pe_indicators', {})
        exe_risk, exe_findings = cls._analyze_pe_indicators(pe_indicators)
        contrib = exe_risk * cls.WEIGHTS['executable_flags']
        risk_score += contrib
        breakdown['binary_flags'] = round(contrib * 100, 1)
        findings.extend(exe_findings)
        explanation_parts.extend(exe_findings)

        risk_score = min(100, max(0, risk_score * 100))

        # Classification
        if risk_score >= 70: classification, color = "MALICIOUS", "#ef4444"
        elif risk_score >= 30: classification, color = "SUSPICIOUS", "#f97316"
        else: classification, color = "SAFE", "#22c55e"

        # ------------------------ Confidence Scoring System ------------------------
        # Confidence is higher if multiple independent sources agree
        signals = [entropy_risk > 0.5, intel_risk > 0, ioc_risk > 0, string_risk > 0.4, mismatch_risk > 0]
        agreeing_signals = sum(1 for s in signals if s)
        base_confidence = 40 if risk_score < 10 else 60
        confidence_score = min(100, base_confidence + (agreeing_signals * 12))
        
        # Penalize if signals are contradictory
        if risk_score > 80 and intel_verdict == 'clean':
            confidence_score -= 20 # Contradiction

        explanation = cls._build_explanation(classification, explanation_parts)

        return {
            'risk_score': round(risk_score, 1),
            'classification': classification,
            'color': color,
            'findings': findings,
            'explanation': explanation,
            'confidence_score': confidence_score,
            'risk_components': breakdown,
            'detailed': {
                'entropy_risk': entropy_risk,
                'malware_risk': malware_risk,
                'threat_intel_risk': intel_risk,
                'ioc_risk': ioc_risk,
                'string_risk': string_risk,
                'mismatch_risk': mismatch_info.get('is_mismatch', False),
                'pe_risk': exe_risk,
            }
        }

    @classmethod
    def _analyze_entropy(cls, entropy: float) -> Tuple[float, List[str]]:
        if entropy > 7.5:
            return 1.0, ["Very high entropy (packed/encrypted)"]
        elif entropy > 7.0:
            return 0.7, ["High entropy (possibly packed)"]
        elif entropy > 6.5:
            return 0.4, ["Moderately high entropy"]
        elif entropy < 2.0:
            return 0.1, ["Very low entropy (homogeneous data)"]
        else:
            return 0.0, []

    @classmethod
    def _analyze_iocs(cls, iocs: Dict[str, List[str]]) -> Tuple[float, List[str]]:
        findings = []
        risk = 0.0

        total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))
        if total_iocs == 0:
            return 0.0, []

        external_ips = 0
        for ip in iocs.get('ips', []):
            if cls._is_external_ip(ip):
                external_ips += 1

        if external_ips > 0:
            risk += min(0.8, external_ips * 0.15)
            findings.append(f"Contains {external_ips} external IP addresses")

        if iocs.get('urls'):
            url_count = len(iocs['urls'])
            risk += min(0.6, url_count * 0.1)
            findings.append(f"Contains {url_count} URLs")

        if iocs.get('domains'):
            domain_count = len(iocs['domains'])
            risk += min(0.5, domain_count * 0.08)
            findings.append(f"Contains {domain_count} domains")

        if iocs.get('emails'):
            risk += 0.2
            findings.append(f"Contains {len(iocs['emails'])} email addresses")

        file_size_mb = iocs.get('_file_size_mb', 1.0)
        density = total_iocs / max(1.0, file_size_mb)
        if density > 10:
            risk += 0.4
            findings.append(f"High IOC density ({density:.1f} IOCs/MB)")

        return min(1.0, risk), findings

    @classmethod
    def _is_external_ip(cls, ip: str) -> bool:
        try:
            parts = [int(p) for p in ip.split('.')]
            if parts[0] == 10:
                return False
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return False
            if parts[0] == 192 and parts[1] == 168:
                return False
            if parts[0] == 127:
                return False
            return True
        except:
            return False

    @classmethod
    def _analyze_suspicious_strings(cls, strings: List[Dict]) -> Tuple[float, List[str]]:
        if not strings:
            return 0.0, []

        total_severity = sum(s.get('severity', 1) for s in strings)
        risk = min(1.0, total_severity / 20.0)

        high_sev = sum(1 for s in strings if s.get('severity', 0) >= 3)
        if high_sev > 0:
            return risk, [f"Found {high_sev} high-severity suspicious strings"]
        elif strings:
            return risk, [f"Found {len(strings)} suspicious strings"]
        return risk, []

    @classmethod
    def _analyze_pe_indicators(cls, indicators: Dict) -> Tuple[float, List[str]]:
        risk = 0.0
        findings = []

        if indicators.get('is_pe', False):
            if indicators.get('has_few_imports', False):
                risk += 0.6
                findings.append("Very few imports (possible packer)")
            if indicators.get('high_entropy_sections', 0) > 0:
                risk += 0.4 * indicators['high_entropy_sections']
                findings.append(f"{indicators['high_entropy_sections']} high-entropy PE sections")
            if indicators.get('is_packed', False):
                risk += 0.8
                findings.append("PE file appears packed")

        return min(1.0, risk), findings

    @classmethod
    def _build_explanation(cls, classification: str, parts: List[str]) -> str:
        if not parts:
            return f"This file is classified as {classification} with no significant indicators."

        first = parts[0] if parts else ""
        rest = parts[1:]

        if classification == "MALICIOUS":
            intro = "This file is classified as MALICIOUS because:\n"
        elif classification == "SUSPICIOUS":
            intro = "This file is classified as SUSPICIOUS because:\n"
        else:
            intro = "This file appears SAFE. Minor observations:\n"

        bullet = "\n".join(f"• {p}" for p in ([first] + rest)[:5])
        return intro + bullet


# ------------------------ MITRE ATT&CK Mapping Engine ------------------------
class MitreMapper:
    """
    Maps analysis findings to MITRE ATT&CK techniques based on identified signals.
    """
    MAPPING_RULES = {
        "persistence": [
            {"id": "T1547", "name": "Boot or Logon Autostart Execution", "keywords": ["runonce", "software\\microsoft\\windows\\currentversion\\run"]},
            {"id": "T1543", "name": "Create or Modify System Process", "keywords": ["services.exe", "create-service"]},
        ],
        "execution": [
            {"id": "T1059", "name": "Command and Scripting Interpreter", "keywords": ["powershell", "cmd.exe", "wscript", "cscript", "bash"]},
            {"id": "T1204", "name": "User Execution", "keywords": ["clicked", "opened", "executed"]},
        ],
        "defense_evasion": [
            {"id": "T1027", "name": "Obfuscated Files or Information", "keywords": ["base64", "encoded", "packed", "encrypted"]},
            {"id": "T1070", "name": "Indicator Removal", "keywords": ["wevtutil", "clearev", "del /f /q"]},
            {"id": "T1027.002", "name": "Software Packing", "keywords": ["packed", "upx", "themida"]},
        ],
        "discovery": [
            {"id": "T1082", "name": "System Information Discovery", "keywords": ["systeminfo", "hostname", "whoami"]},
            {"id": "T1016", "name": "System Network Configuration Discovery", "keywords": ["ipconfig", "netstat", "route print"]},
        ],
        "credential_access": [
            {"id": "T1552", "name": "Unsecured Credentials", "keywords": ["password", "passwd", "token", "api_key", "secret"]},
            {"id": "T1003", "name": "OS Credential Dumping", "keywords": ["lsass", "mimikatz", "procdump"]},
        ],
        "c2": [
            {"id": "T1071", "name": "Application Layer Protocol", "keywords": ["http://", "https://", "ftp://"]},
            {"id": "T1573", "name": "Encrypted Channel", "keywords": ["tls", "ssl", "encrypted"]},
        ],
    }

    @classmethod
    def map_to_mitre(cls, results: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        techniques = []
        seen_ids = set()

        # Check suspicious strings
        susp_strings = results.get("suspicious_strings", [])
        for s_info in susp_strings:
            s_text = s_info.get("string", "").lower()
            for tactic, rules in cls.MAPPING_RULES.items():
                for rule in rules:
                    if rule["id"] in seen_ids:
                        continue
                    if any(kw in s_text for kw in rule["keywords"]):
                        techniques.append({
                            "id": rule["id"],
                            "name": rule["name"],
                            "tactic": tactic.replace("_", " ").title(),
                            "confidence": min(1.0, s_info.get("severity", 1) / 5.0),
                            "source": f"Suspicious string: {rule['id']}"
                        })
                        seen_ids.add(rule["id"])

        # Check IOCs
        iocs = results.get("iocs", {})
        if iocs.get("external_ips") or iocs.get("suspicious_domains"):
            t_id = "T1071"
            if t_id not in seen_ids:
                techniques.append({
                    "id": t_id,
                    "name": "Application Layer Protocol",
                    "tactic": "Command and Control",
                    "confidence": 0.8,
                    "source": "External IP/Domain detected"
                })
                seen_ids.add(t_id)

        # Check PE Indicators
        pe = results.get("pe_indicators", {})
        if pe.get("is_packed"):
            t_id = "T1027.002"
            if t_id not in seen_ids:
                techniques.append({
                    "id": t_id,
                    "name": "Software Packing",
                    "tactic": "Defense Evasion",
                    "confidence": 0.9,
                    "source": "Packed executable detected"
                })
                seen_ids.add(t_id)

        # Check Mismatch
        mismatch = results.get("file_mismatch", {})
        if mismatch.get("is_mismatch"):
            t_id = "T1027"
            if t_id not in seen_ids:
                techniques.append({
                    "id": t_id,
                    "name": "Obfuscated Files or Information",
                    "tactic": "Defense Evasion",
                    "confidence": 0.7,
                    "source": "File type/extension mismatch"
                })
                seen_ids.add(t_id)

        return {"techniques": sorted(techniques, key=lambda x: x["confidence"], reverse=True)}


# ------------------------ Case-Level Correlation Engine ------------------------
class CaseAnalyzer:
    """
    Analyzes multiple file results together to identify shared indicators and case-level risk.
    """
    @classmethod
    def analyze(cls, case_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not case_results:
            return {}

        shared_iocs = defaultdict(list)
        shared_hashes = defaultdict(list)
        ip_map = defaultdict(list)
        domain_map = defaultdict(list)
        high_risk_files = []
        total_risk_score = 0.0

        for res in case_results:
            path = res.get("file_path", "Unknown")
            fname = os.path.basename(path)
            
            # Risk Accumulation
            analysis = res.get("analysis", {})
            score = analysis.get("risk_score", 0.0)
            total_risk_score += score
            if score >= 60:
                high_risk_files.append({"name": fname, "score": score})

            # Hash Correlation
            hashes = res.get("hashes", {})
            sha256 = hashes.get("sha256")
            if sha256:
                shared_hashes[sha256].append(fname)

            # IOC Correlation
            iocs = res.get("iocs", {})
            for ip in iocs.get("ips", []):
                ip_map[ip].append(fname)
            for dom in iocs.get("domains", []):
                domain_map[dom].append(fname)

        # Filter shared
        correlated_ips = {ip: files for ip, files in ip_map.items() if len(files) > 1}
        correlated_domains = {dom: files for dom, files in domain_map.items() if len(files) > 1}
        correlated_hashes = {h: files for h, files in shared_hashes.items() if len(files) > 1}

        # Case Summary
        avg_risk = total_risk_score / len(case_results)
        case_risk = "SAFE"
        if avg_risk >= 70 or any(f["score"] >= 90 for f in high_risk_files):
            case_risk = "MALICIOUS"
        elif avg_risk >= 30 or high_risk_files:
            case_risk = "SUSPICIOUS"

        summary_parts = []
        if correlated_hashes:
            summary_parts.append(f"{len(correlated_hashes)} identical files detected across the case.")
        if correlated_ips:
            summary_parts.append(f"{len(correlated_ips)} IP addresses shared between multiple files.")
        if correlated_domains:
            summary_parts.append(f"{len(correlated_domains)} domains shared between multiple files.")
        
        if not summary_parts:
            summary_text = "No strong correlations found between items in this case."
        else:
            summary_text = " ".join(summary_parts)

        return {
            "case_risk": case_risk,
            "avg_score": round(avg_risk, 1),
            "shared_iocs": {"ips": correlated_ips, "domains": correlated_domains},
            "shared_hashes": correlated_hashes,
            "high_risk_files": high_risk_files,
            "correlation_summary": summary_text
        }


# ------------------------ Forensic Report Generator ------------------------
class ReportGenerator:
    """
    Generates professional-grade forensic reports in HTML format.
    """
    HTML_TEMPLATE = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>ForensiX Intelligence Report</title>
        <style>
            :root {{
                --bg: #020617;
                --card: #0f172a;
                --text: #f8fafc;
                --dim: #94a3b8;
                --primary: #38bdf8;
                --danger: #ef4444;
                --warning: #f97316;
                --success: #22c55e;
            }}
            body {{ font-family: 'Inter', -apple-system, blinkmacsystemfont, 'Segoe UI', roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.5; margin: 0; padding: 40px; }}
            .container {{ max-width: 1100px; margin: 0 auto; }}
            header {{ border-bottom: 2px solid #1e293b; padding-bottom: 20px; margin-bottom: 40px; }}
            h1 {{ margin: 0; color: var(--primary); font-size: 36px; letter-spacing: -1px; }}
            h2 {{ border-left: 4px solid var(--primary); padding-left: 15px; margin-top: 45px; color: var(--primary); font-size: 24px; }}
            .risk-badge {{ display: inline-block; padding: 12px 24px; border-radius: 8px; font-weight: 800; font-size: 22px; margin: 15px 0; letter-spacing: 1px; }}
            .risk-MALICIOUS {{ background: var(--danger); box-shadow: 0 0 20px rgba(239, 68, 68, 0.3); }}
            .risk-SUSPICIOUS {{ background: var(--warning); box-shadow: 0 0 20px rgba(249, 115, 22, 0.3); }}
            .risk-SAFE {{ background: var(--success); box-shadow: 0 0 20px rgba(34, 197, 94, 0.3); }}
            .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
            .card {{ background: var(--card); padding: 25px; border-radius: 12px; border: 1px solid #1e293b; transition: border-color 0.2s; }}
            .label {{ color: var(--dim); font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px; }}
            .value {{ font-family: 'JetBrains Mono', 'Fira Code', monospace; word-break: break-all; font-size: 13px; margin-bottom: 12px; color: #cbd5e1; }}
            .section-desc {{ color: var(--dim); font-size: 14px; margin-bottom: 20px; }}
            .mitre-pill {{ display: inline-block; background: #1e293b; border: 1px solid #334155; padding: 6px 12px; border-radius: 6px; margin: 4px; font-size: 13px; }}
            .rec-action {{ background: rgba(56, 189, 248, 0.1); border: 1px solid var(--primary); color: var(--primary); padding: 10px; border-radius: 6px; margin-bottom: 8px; font-weight: bold; }}
            .anomaly-alert {{ background: rgba(239, 68, 68, 0.1); border: 1px solid var(--danger); color: var(--danger); padding: 10px; border-radius: 6px; margin-bottom: 8px; }}
            .timeline-item {{ border-left: 2px solid #1e293b; padding-left: 20px; position: relative; margin-bottom: 15px; font-size: 13px; }}
            .timeline-item::before {{ content: ''; position: absolute; left: -7px; top: 5px; width: 12px; height: 12px; background: var(--primary); border-radius: 50%; }}
            .stat-bar {{ height: 8px; background: #1e293b; border-radius: 4px; overflow: hidden; margin-top: 5px; }}
            .stat-fill {{ height: 100%; background: var(--primary); }}
            footer {{ margin-top: 80px; padding-top: 20px; border-top: 1px solid #1e293b; text-align: center; color: var(--dim); font-size: 12px; letter-spacing: 1px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>ForensiX Intelligence Platform</h1>
                <p>Advanced Forensic Analysis | {timestamp} | Case ID: {case_id}</p>
            </header>

            <section>
                <h2>1. Executive Intelligence Summary</h2>
                <div class="card">
                    <div class="grid">
                        <div>
                            <p class="label">Primary Verdict</p>
                            <div class="risk-badge risk-{classification}">{classification}</div>
                            <p class="label">Platform Risk Score</p>
                            <p class="value" style="font-size: 24px; color: var(--primary);">{score} / 100</p>
                            <p class="label">Analysis Confidence</p>
                            <p class="value">{confidence_score}%</p>
                        </div>
                        <div>
                            <p class="label">Risk Breakdown</p>
                            {breakdown_html}
                        </div>
                    </div>
                    <p class="label" style="margin-top: 20px;">Analyst Conclusion</p>
                    <p>{explanation}</p>
                </div>
            </section>

            <section>
                <h2>2. Malware Classification & Profiling</h2>
                <div class="grid">
                    <div class="card">
                        <p class="label">Family Classification</p>
                        <p class="value" style="font-size: 20px; color: var(--warning);">{malware_family}</p>
                        <p class="label">Heuristic Reasoning</p>
                        <p style="font-size: 13px;">{family_reasoning}</p>
                    </div>
                    <div class="card">
                        <p class="label">Behavioral Profile</p>
                        {behavior_html}
                    </div>
                </div>
            </section>

            <section>
                <h2>3. Impact & Recommendations</h2>
                <div class="grid">
                    <div class="card" style="border-color: var(--danger);">
                        <p class="label">Forensic Impact Assessment</p>
                        {impact_html}
                    </div>
                    <div class="card" style="border-color: var(--success);">
                        <p class="label">Mandatory Analyst Actions</p>
                        {recommendation_html}
                    </div>
                </div>
            </section>

            <section>
                <h2>4. Anomalies & Structural Analysis</h2>
                <div class="card">
                    {anomaly_html}
                </div>
            </section>

            <section>
                <h2>5. Technical Attribution (MITRE ATT&CK)</h2>
                <div class="card">
                    <p class="section-desc">Observed techniques mapped to the MITRE ATT&CK knowledge base.</p>
                    {mitre_html}
                </div>
            </section>

            <section>
                <h2>6. Indicators of Compromise</h2>
                <div class="grid">
                    <div class="card">
                        <p class="label">Threat Intel Hits (VirusTotal)</p>
                        <p class="value" style="font-size: 18px;">{intel_hits} / {intel_total} Engines</p>
                        <p class="label" style="margin-top: 15px;">Enriched Network Indicators</p>
                        {ioc_html}
                    </div>
                    <div class="card">
                        <p class="label">Suspicious Strings (Forensic context)</p>
                        {strings_html}
                    </div>
                </div>
            </section>

            <section>
                <h2>7. Timeline View</h2>
                <div class="card">
                    {timeline_html}
                </div>
            </section>

            <section>
                <h2>8. File Evidence</h2>
                <div class="grid">
                    <div class="card">
                        <p class="label">File Path</p><p class="value">{filepath}</p>
                        <p class="label">MIME Type</p><p class="value">{mime}</p>
                        <p class="label">File Size</p><p class="value">{filesize}</p>
                    </div>
                    <div class="card">
                        <p class="label">SHA256 Hash</p><p class="value">{sha256}</p>
                        <p class="label">Entropy</p><p class="value">{entropy}</p>
                    </div>
                </div>
            </section>

            <footer>
                ForensiX Studio Pro | Elite Forensic Capability | CONFIDENTIAL FORENSIC PRODUCT
            </footer>
        </div>
    </body>
    </html>
    """

    @classmethod
    @classmethod
    def generate_report(cls, results: Dict[str, Any], output_path: str):
        try:
            analysis = results.get("analysis", {})
            hashes = results.get("hashes", {})
            iocs = results.get("iocs", {})
            mitre = results.get("mitre", {}).get("techniques", [])
            
            # Risk Breakdown HTML
            breakdown_html = ""
            for comp, val in analysis.get('risk_components', {}).items():
                breakdown_html += f'<div style="margin-bottom:8px;"><span class="label">{comp.replace("_", " ")}</span>'
                breakdown_html += f'<div class="stat-bar"><div class="stat-fill" style="width:{val}%"></div></div></div>'

            # Behavior HTML
            behavior_html = "<ul>"
            for b in results.get('behaviors', []):
                behavior_html += f"<li>{b}</li>"
            behavior_html += "</ul>"

            # Impact HTML
            impact_html = ""
            for im in results.get('impact_assessment', {}).get('impacts', []):
                impact_html += f'<div style="color:var(--danger); margin-bottom:5px;">• {im}</div>'
            
            # Recommendation HTML
            rec_html = ""
            for rec in results.get('impact_assessment', {}).get('recommendations', []):
                rec_html += f'<div class="rec-action">{rec}</div>'

            # Anomaly HTML
            anomaly_html = ""
            for a in results.get('anomalies', []):
                anomaly_html += f'<div class="anomaly-alert">{a}</div>'

            # Timeline HTML
            timeline_html = ""
            for ev in results.get('timeline', []):
                t_str = ev['time'].split('T')[1].split('.')[0] if 'T' in ev['time'] else ev['time']
                timeline_html += f'<div class="timeline-item"><b>{t_str}</b>: {ev["event"]}</div>'

            # MITRE HTML
            mitre_html = ""
            for t in mitre:
                mitre_html += f'<div class="mitre-pill"><b>{t["id"]}</b>: {t["name"]} ({t["tactic"]})</div>'
            if not mitre_html: mitre_html = "No specific MITRE techniques mapped."

            # IOC HTML
            ioc_html = "<ul>"
            enriched = results.get('enriched_iocs', {})
            for ip in enriched.get('ips', []):
                ioc_html += f"<li><b>IP:</b> {ip['ip']} ({ip['type']} / {ip['reputation']})</li>"
            for dom in enriched.get('domains', []):
                ioc_html += f"<li><b>Domain:</b> {dom['domain']} (Entropy: {dom['entropy']})</li>"
            ioc_html += "</ul>"

            # Strings HTML
            strings_html = "<ul>"
            for s in results.get("suspicious_strings", [])[:15]:
                strings_html += f'<li class="value" style="font-size:11px;">{s["string"][:60]}...</li>'
            strings_html += "</ul>"

            html = cls.HTML_TEMPLATE.format(
                timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                case_id=results.get("case_id", "UNCATEGORIZED"),
                classification=analysis.get("classification", "UNKNOWN"),
                score=analysis.get("risk_score", 0),
                confidence_score=analysis.get("confidence_score", 0),
                explanation=analysis.get("explanation", "No explanation available.").replace("\n", "<br>"),
                breakdown_html=breakdown_html,
                malware_family=results.get('malware_family', {}).get('family', 'UNKNOWN'),
                family_reasoning=results.get('malware_family', {}).get('reasoning', ''),
                behavior_html=behavior_html,
                impact_html=impact_html,
                recommendation_html=rec_html,
                anomaly_html=anomaly_html,
                mitre_html=mitre_html,
                intel_hits=results.get('threat_intel', {}).get('detections', 0),
                intel_total=results.get('threat_intel', {}).get('total_engines', 0),
                ioc_html=ioc_html,
                strings_html=strings_html,
                timeline_html=timeline_html,
                filepath=results.get("file_path", "N/A"),
                mime=results.get("mime_type", "N/A"),
                filesize=f"{results.get('file_size', 0) / 1024:.2f} KB",
                sha256=hashes.get("sha256", "N/A"),
                entropy=f"{results.get('entropy', 0):.3f}"
            )

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html)
            return True
        except Exception as e:
            logger.error(f"Elite report generation failed: {e}")
            return False


# ------------------------ Threat Intelligence Client ------------------------
class ThreatIntelClient:
    """
    Simulates a Threat Intelligence API client (e.g., VirusTotal) with local caching.
    """
    _cache = {}

    @classmethod
    def lookup_hash(cls, sha256: str, api_key: str = None) -> Dict[str, Any]:
        if sha256 in cls._cache:
            return cls._cache[sha256]

        # In a real tool, this would be a requests.get call
        # For this production-grade sim, we handle the logic and default unknown
        result = {
            "detections": 0,
            "total_engines": 0,
            "verdict": "unknown",
            "last_analysis": None,
            "provider": "VirusTotal (Simulated)"
        }

        # Safe fallback logic if no key or network simulation
        if not api_key:
            return result

        try:
            # Simulate logic for detections based on some internal rules for demo/testing
            # In production, this block would perform the actual API request
            pass
        except Exception as e:
            logger.error(f"Threat Intel API error: {e}")

        cls._cache[sha256] = result
        return result


# ------------------------ IOC Enrichment Engine ------------------------
class IOCEnricher:
    """
    Enriches indicators of compromise with reputation and classification data.
    """
    SUSPICIOUS_TLDS = {'.ru', '.xyz', '.top', '.club', '.work', '.tk', '.ml', '.ga', '.cf', '.gq'}

    @classmethod
    def enrich(cls, iocs: Dict[str, List[str]]) -> Dict[str, Any]:
        enriched = {
            "ips": [],
            "domains": []
        }

        # IP Enrichment
        processed_ips = set()
        for ip in iocs.get('ips', []):
            if ip in processed_ips: continue
            processed_ips.add(ip)

            is_private = cls._is_private_ip(ip)
            entry = {
                "ip": ip,
                "type": "internal" if is_private else "external",
                "reputation": "safe" if is_private else "unknown",
                "threat_score": 0 if is_private else 10
            }
            enriched["ips"].append(entry)

        # Domain Enrichment
        processed_domains = set()
        for domain in iocs.get('domains', []):
            if domain in processed_domains: continue
            processed_domains.add(domain)

            tld = '.' + domain.split('.')[-1] if '.' in domain else ''
            is_suspicious_tld = tld.lower() in cls.SUSPICIOUS_TLDS
            entropy = cls._calculate_entropy(domain)

            entry = {
                "domain": domain,
                "tld": tld,
                "is_suspicious_tld": is_suspicious_tld,
                "entropy": round(entropy, 2),
                "is_dga_candidate": entropy > 3.8,
                "threat_score": (30 if is_suspicious_tld else 0) + (20 if entropy > 3.8 else 0)
            }
            enriched["domains"].append(entry)

        return enriched

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        try:
            parts = [int(p) for p in ip.split('.')]
            if parts[0] == 10: return True
            if parts[0] == 172 and 16 <= parts[1] <= 31: return True
            if parts[0] == 192 and parts[1] == 168: return True
            if parts[0] == 127: return True
            return False
        except: return False

    @staticmethod
    def _calculate_entropy(s: str) -> float:
        if not s: return 0.0
        freq = {}
        for ch in s: freq[ch] = freq.get(ch, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / len(s)
            entropy -= p * math.log2(p)
        return entropy


# ------------------------ Malware Family Classifier ------------------------
class MalwareClassifier:
    """
    Infers malware category based on behavioral signals and indicators.
    """
    @classmethod
    def classify(cls, results: Dict[str, Any]) -> Dict[str, Any]:
        signals = []
        family = "unknown"
        confidence = 0.0
        reasons = []

        strings = [s['string'].lower() for s in results.get('suspicious_strings', [])]
        mitre = [t['id'] for t in results.get('mitre', {}).get('techniques', [])]
        iocs = results.get('iocs', {})
        
        # Heuristic rules
        ransomware_signals = ['wallet', 'decrypt', 'bitcoin', 'ransom', '.enc', '.crypt']
        infostealer_signals = ['token', 'cookie', 'session', 'login', 'password', 'autofill']
        rat_signals = ['reverse', 'shell', 'bind', 'connect', 'upload', 'screen']
        loader_signals = ['download', 'execute', 'webclient', 'bitsadmin', 'curl']

        counts = {
            "ransomware": sum(1 for s in strings if any(x in s for x in ransomware_signals)),
            "infostealer": sum(1 for s in strings if any(x in s for x in infostealer_signals)),
            "RAT": sum(1 for s in strings if any(x in s for x in rat_signals)),
            "loader": sum(1 for s in strings if any(x in s for x in loader_signals))
        }

        # Refine based on MITRE
        if "T1059" in mitre: counts["loader"] += 1
        if "T1071" in mitre: counts["RAT"] += 1
        if "T1552" in mitre: counts["infostealer"] += 1

        best_family = max(counts, key=counts.get)
        if counts[best_family] > 0:
            family = best_family
            confidence = min(0.9, counts[best_family] * 0.2)
            reasons.append(f"Identified {counts[best_family]} behavioral matches for {best_family}")
        
        if results.get('entropy', 0) > 7.2:
            reasons.append("High entropy suggests packing (common in malware loaders)")

        return {
            "family": family.upper(),
            "confidence": round(confidence, 2),
            "reasoning": " | ".join(reasons) if reasons else "No clear behavioral family identified."
        }


# ------------------------ Behavioral Profile Engine ------------------------
class BehaviorProfiler:
    """
    Generates a structured description of observed file behavior.
    """
    @classmethod
    def profile(cls, results: Dict[str, Any]) -> List[str]:
        behaviors = []
        mitre = results.get('mitre', {}).get('techniques', [])
        iocs = results.get('iocs', {})
        pe = results.get('pe_indicators', {})

        if any(t['tactic'] == 'Persistence' for t in mitre):
            behaviors.append("Attempts to maintain persistence on the system")
        if any(t['tactic'] == 'Command And Control' for t in mitre) or iocs.get('external_ips'):
            behaviors.append("Communicates with external Command & Control servers")
        if any(t['tactic'] == 'Credential Access' for t in mitre):
            behaviors.append("Actively targets system or user credentials")
        if any(t['tactic'] == 'Defense Evasion' for t in mitre) or pe.get('is_packed'):
            behaviors.append("Employs obfuscation or anti-analysis techniques")
        if any(t['id'] == 'T1059' for t in mitre):
            behaviors.append("Executes commands via system interpreters")
        
        if not behaviors:
            behaviors.append("No significant malicious behaviors identified.")

        return behaviors


# ------------------------ Impact Assessment Engine ------------------------
class ImpactAnalyzer:
    """
    Explains forensic consequences and provides analyst recommendations.
    """
    @classmethod
    def analyze(cls, classification: str, family_info: Dict[str, Any], risk_score: float) -> Dict[str, List[str]]:
        impacts = []
        recommendations = []

        family = family_info.get("family", "UNKNOWN")

        if risk_score > 70:
            impacts.append("Critical risk of system compromise")
        
        if family == "RANSOMWARE":
            impacts.append("Risk of data encryption and extortion")
            recommendations.append("Immediately disconnect system from network")
            recommendations.append("Check for shadow copy deletion attempts")
        elif family == "INFOSTEALER":
            impacts.append("Account credentials and session tokens at risk")
            recommendations.append("Force change of all passwords for affected users")
            recommendations.append("Invalidate active web sessions")
        elif family == "RAT":
            impacts.append("Attacker has full remote access to system")
            recommendations.append("Full forensic imaging required")
            recommendations.append("Identify and block C2 IP addresses")
        elif family == "LOADER":
            impacts.append("System used as a staging ground for further infections")
            recommendations.append("Scan for subsequent stage-2 payloads")

        if classification == "MALICIOUS":
            recommendations.append("Do NOT execute this file")
            recommendations.append("Isolate the host immediately")
        elif classification == "SUSPICIOUS":
            recommendations.append("Run in isolated sandbox for dynamic analysis")
            recommendations.append("Monitor for unusual network activity")
        
        if not recommendations:
            recommendations.append("Standard security monitoring recommended.")

        return {
            "impacts": impacts if impacts else ["Potential minor security concern"],
            "recommendations": recommendations
        }


# ------------------------ Advanced Timeline Correlation ------------------------
class TimelineBuilder:
    """
    Converts raw forensic timestamps and findings into a chronological sequence.
    """
    @classmethod
    def build(cls, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        events = []
        path = results.get("file_path", "")
        
        # Timestamps
        if os.path.exists(path):
            st = os.stat(path)
            events.append({"time": datetime.datetime.fromtimestamp(st.st_ctime).isoformat(), "event": "File created on disk"})
            events.append({"time": datetime.datetime.fromtimestamp(st.st_mtime).isoformat(), "event": "Last modification recorded"})
        
        # Analysis findings
        if results.get('analysis'):
            t_now = datetime.datetime.now().isoformat()
            events.append({"time": t_now, "event": f"Automated analysis completed (Risk: {results['analysis']['classification']})"})

        for t in results.get('mitre', {}).get('techniques', []):
            events.append({"time": t_now, "event": f"MITRE Technique detected: {t['name']}"})

        for ip in results.get('iocs', {}).get('external_ips', []):
            events.append({"time": t_now, "event": f"External C2 indicator found: {ip}"})

        events.sort(key=lambda x: x['time'])
        return events


# ------------------------ Anomaly Detection Engine ------------------------
class AnomalyDetector:
    """
    Detects inconsistencies in file structure and metadata.
    """
    @classmethod
    def detect(cls, results: Dict[str, Any]) -> List[str]:
        anomalies = []
        mismatch = results.get('file_mismatch', {})
        entropy = results.get('entropy', 0)
        pe = results.get('pe_indicators', {})

        if mismatch.get('is_mismatch'):
            anomalies.append(f"Format anomaly: {mismatch.get('explanation')}")
        
        if entropy > 7.5:
            anomalies.append("Extremely high entropy: Indicates advanced encryption or packing")
        
        if pe.get('is_pe') and pe.get('import_count', 0) < 5:
            anomalies.append("Abnormal binary: Suspiciously low number of imports")
        
        if not anomalies:
            anomalies.append("No significant structural anomalies detected.")
            
        return anomalies


# ------------------------ Full Analysis Worker ------------------------
class FullAnalysisWorker(QThread):
    progress = Signal(str)
    finished = Signal(dict)

    def __init__(self, file_path: str, known_bad_hashes: set):
        super().__init__()
        self.file_path = file_path
        self.known_bad_hashes = known_bad_hashes
        self.file_size = os.path.getsize(file_path)

    def run(self):
        results = {
            'file_path': self.file_path,
            'file_size': self.file_size,
        }
        try:
            read_limit = 10 * 1024 * 1024
            with open(self.file_path, "rb") as f:
                data = f.read(read_limit)

            self.progress.emit("Computing hashes...")
            hashes = compute_hashes(self.file_path)
            results['hashes'] = hashes

            self.progress.emit("Querying Threat Intelligence...")
            threat_intel = ThreatIntelClient.lookup_hash(hashes.get('sha256', ''), api_key="SIMULATED_KEY")
            results['threat_intel'] = threat_intel

            self.progress.emit("Calculating entropy...")
            entropy = estimate_entropy(self.file_path)
            results['entropy'] = entropy

            self.progress.emit("Analyzing file type...")
            mime_type = mimetypes.guess_type(self.file_path)[0]
            magic_desc = detect_magic_label(file_magic(self.file_path, 8))
            results['magic_desc'] = magic_desc
            results['mime_type'] = mime_type
            mismatch = FileMismatchDetector.detect(self.file_path, mime_type)
            results['file_mismatch'] = mismatch

            self.progress.emit("Running malware scoring...")
            malware_info = MalwareScorer.score_file(self.file_path, entropy, magic_desc, self.known_bad_hashes)
            results['malware_score'] = malware_info['score']
            results['malware_reasons'] = malware_info['reasons']

            self.progress.emit("Extracting strings...")
            strings = self._extract_strings(data)
            results['all_strings'] = strings
            self.progress.emit("Analyzing suspicious strings...")
            suspicious = SuspiciousStringAnalyzer.analyze(strings)
            results['suspicious_strings'] = suspicious

            self.progress.emit("Extracting and Enriching IOCs...")
            base_iocs = EnhancedIOCExtractor.extract_with_classification(data, self.file_size)
            enriched_iocs = IOCEnricher.enrich(base_iocs)
            results['iocs'] = base_iocs # Keep base for backward compat
            results['enriched_iocs'] = enriched_iocs

            results['pe_indicators'] = self._analyze_pe()

            self.progress.emit("Mapping to MITRE ATT&CK...")
            mitre_info = MitreMapper.map_to_mitre(results)
            results['mitre'] = mitre_info

            self.progress.emit("Performing intelligence correlation...")
            analysis = AnalysisEngine.analyze(results)
            results['analysis'] = analysis

            self.progress.emit("Classifying malware family...")
            family_info = MalwareClassifier.classify(results)
            results['malware_family'] = family_info

            self.progress.emit("Profiling behavioral patterns...")
            behaviors = BehaviorProfiler.profile(results)
            results['behaviors'] = behaviors

            self.progress.emit("Assessing potential impact...")
            impact_data = ImpactAnalyzer.analyze(analysis['classification'], family_info, analysis['risk_score'])
            results['impact_assessment'] = impact_data

            self.progress.emit("Detecting structural anomalies...")
            anomalies = AnomalyDetector.detect(results)
            results['anomalies'] = anomalies

            self.progress.emit("Building forensic timeline...")
            timeline = TimelineBuilder.build(results)
            results['timeline'] = timeline

            self.progress.emit("Analysis complete.")
            self.finished.emit(results)

        except Exception as e:
            logger.error(f"Full analysis error: {e}", exc_info=True)
            self.progress.emit(f"Analysis failed: {e}")
            self.finished.emit({'error': str(e)})

    def _extract_strings(self, data: bytes, min_len: int = 4) -> List[str]:
        strings = []
        cur = []
        for b in data:
            if 32 <= b < 127:
                cur.append(chr(b))
            else:
                if len(cur) >= min_len:
                    strings.append("".join(cur))
                cur = []
        if len(cur) >= min_len:
            strings.append("".join(cur))
        try:
            u = data.decode("utf-16-le", errors="ignore")
            cur = []
            for ch in u:
                if 32 <= ord(ch) < 127:
                    cur.append(ch)
                else:
                    if len(cur) >= min_len:
                        strings.append("".join(cur))
                    cur = []
            if len(cur) >= min_len:
                strings.append("".join(cur))
        except:
            pass
        return strings

    def _analyze_pe(self) -> Dict[str, Any]:
        indicators = {'is_pe': False}
        if not PEFILE_AVAILABLE:
            return indicators
        try:
            pe = pefile.PE(self.file_path)
            indicators['is_pe'] = True
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                indicators['import_count'] = len(pe.DIRECTORY_ENTRY_IMPORT)
                indicators['has_few_imports'] = indicators['import_count'] < 3
            high_entropy_sections = 0
            for sect in pe.sections:
                if sect.get_entropy() > 7.0:
                    high_entropy_sections += 1
            indicators['high_entropy_sections'] = high_entropy_sections
            indicators['is_packed'] = high_entropy_sections >= 2 or indicators.get('has_few_imports', False)
        except:
            pass
        return indicators


# ------------------------ File Carver ------------------------
class FileCarver:
    SIGNATURES = [
        (b"%PDF", "PDF Document", "pdf"),
        (b"\xff\xd8\xff", "JPEG Image", "jpg"),
        (b"\x89PNG", "PNG Image", "png"),
        (b"PK\x03\x04", "ZIP Archive", "zip"),
    ]

    @staticmethod
    def carve(path: str, output_dir: str) -> list:
        results = []
        try:
            with open(path, "rb") as f:
                data = f.read(10 * 1024 * 1024)
            for sig, label, ext in FileCarver.SIGNATURES:
                start = 0
                while True:
                    pos = data.find(sig, start)
                    if pos == -1:
                        break
                    end_pos = min(len(data), pos + 5 * 1024 * 1024)
                    if ext == "pdf":
                        eof = data.find(b"%%EOF", pos)
                        if eof != -1:
                            end_pos = eof + 5
                    if ext == "jpg":
                        eof = data.find(b"\xff\xd9", pos)
                        if eof != -1:
                            end_pos = eof + 2
                    out_name = f"carved_{pos:08X}.{ext}"
                    out_path = os.path.join(output_dir, out_name)
                    with open(out_path, "wb") as f_out:
                        f_out.write(data[pos:end_pos])
                    results.append(out_path)
                    start = pos + 1
        except Exception as e:
            logger.error(f"Carving error: {e}")
        return results


# ------------------------ Command Palette Dialog ------------------------
class CommandPaletteDialog(QtWidgets.QDialog):
    def __init__(self, parent, commands: dict):
        super().__init__(parent)
        self.setWindowTitle("Command Palette")
        self.resize(600, 400)
        self.layout = QtWidgets.QVBoxLayout(self)
        self.search_edit = QtWidgets.QLineEdit()
        self.search_edit.setPlaceholderText("Type a command...")
        self.layout.addWidget(self.search_edit)
        self.list_widget = QtWidgets.QListWidget()
        self.layout.addWidget(self.list_widget)
        self.commands = commands
        self.filtered = []
        self.search_edit.textChanged.connect(self.update_list)
        self.list_widget.itemActivated.connect(self.execute)
        self.update_list("")
        self.setStyleSheet("""
            QDialog { background-color: #0f172a; color: #e2e8f0; }
            QLineEdit { padding: 8px; border: 1px solid #334155; border-radius: 4px; background: #1e293b; color: #fff; font-size: 14px; }
            QListWidget { border: none; background: #0f172a; }
            QListWidget::item { padding: 8px; border-bottom: 1px solid #1e293b; color: #cbd5e1; }
            QListWidget::item:selected { background: #334155; color: #fff; }
        """)

    def update_list(self, text):
        self.list_widget.clear()
        self.filtered = []
        text = text.lower()
        for name in sorted(self.commands.keys()):
            if text in name.lower():
                self.filtered.append(name)
                self.list_widget.addItem(name)
        if self.list_widget.count() > 0:
            self.list_widget.setCurrentRow(0)

    def execute(self, item=None):
        if not item:
            item = self.list_widget.currentItem()
        if not item:
            return
        cmd_name = item.text()
        callback = self.commands.get(cmd_name)
        if callback:
            self.accept()
            callback()


# ------------------------ Main Window ------------------------
class FileInsightWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.resize(1600, 900)

        self.current_path: Optional[str] = None
        self.current_mime: Optional[str] = None
        self.time_mode = "local"
        self.evidence_mode = True
        self.dark_mode = True

        self.cases: Dict[str, Dict] = {}
        self.current_case_id: Optional[str] = None
        self.case_counter = 1
        self.evidence_counter = 1
        self.evidence_db: Dict[str, Dict] = {}
        self.known_good = set()
        self.known_bad = set()
        self.current_archive_entries = []

        self.last_extracted_strings = []
        self.last_iocs = {}
        self.last_suspicious_strings = []

        self._custody_key = os.urandom(32)

        self._build_ui()
        self._apply_style()
        self.load_state()
        if not self.cases:
            self._create_default_case()
        else:
            self._refresh_case_combo()
            if self.current_case_id in self.cases:
                self.populate_evidence_list()
        self.update_dashboard()
        self.update_timeline()

        QtGui.QShortcut(QtGui.QKeySequence("Ctrl+O"), self, self.choose_file)
        QtGui.QShortcut(QtGui.QKeySequence("Ctrl+Shift+R"), self, self.export_report)
        QtGui.QShortcut(QtGui.QKeySequence("F5"), self, self.reverify_hashes)
        QtGui.QShortcut(QtGui.QKeySequence("Ctrl+E"), self, self.encrypt_current_file)
        QtGui.QShortcut(QtGui.QKeySequence("Ctrl+D"), self, self.decrypt_file_dialog)
        QtGui.QShortcut(QtGui.QKeySequence("Ctrl+Shift+S"), self, self.extract_strings)
        QtGui.QShortcut(QtGui.QKeySequence("Ctrl+Shift+A"), self, self.analyze_case)
        QtGui.QShortcut(QtGui.QKeySequence("Ctrl+Shift+P"), self, self.show_command_palette)

        self.commands = {
            "Open File": self.choose_file,
            "Export Report": self.export_report,
            "Reverify Hashes": self.reverify_hashes,
            "Encrypt File": self.encrypt_current_file,
            "Decrypt File": self.decrypt_file_dialog,
            "Extract Strings": self.extract_strings,
            "Analyze Case": self.analyze_case,
            "Toggle Dark/Light Mode": self.toggle_dark_mode,
            "Show Command Palette": self.show_command_palette,
            "Secure Wipe File": self.secure_wipe_current,
            "Generate Malware Score": self.run_malware_scan,
            "Run Full Analysis": self.run_full_analysis,
        }

        self.setAcceptDrops(True)

    # ------------------------ UI Construction ------------------------
    def _build_ui(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu("&File")
        view_menu = menubar.addMenu("&View")
        tools_menu = menubar.addMenu("&Tools")
        help_menu = menubar.addMenu("&Help")

        act_open = QtGui.QAction("Open File...", self)
        act_open.setShortcut("Ctrl+O")
        act_open.triggered.connect(self.choose_file)
        file_menu.addAction(act_open)

        act_import_case = QtGui.QAction("Import Case...", self)
        act_export_case = QtGui.QAction("Export Case...", self)
        file_menu.addSeparator()
        file_menu.addAction(act_import_case)
        file_menu.addAction(act_export_case)

        act_palette = QtGui.QAction("Command Palette", self)
        act_palette.setShortcut("Ctrl+Shift+P")
        act_palette.triggered.connect(self.show_command_palette)
        view_menu.addAction(act_palette)

        act_toggle_theme = QtGui.QAction("Toggle Dark/Light Mode", self)
        act_toggle_theme.triggered.connect(self.toggle_dark_mode)
        view_menu.addAction(act_toggle_theme)

        act_dir_scan = QtGui.QAction("Directory Scan to CSV...", self)
        act_dir_scan.triggered.connect(self.directory_scan)
        tools_menu.addAction(act_dir_scan)

        act_import_good = QtGui.QAction("Import Known-Good Hashes (CSV)...", self)
        act_import_good.triggered.connect(lambda: self.import_hashes(True))
        tools_menu.addAction(act_import_good)

        act_import_bad = QtGui.QAction("Import Known-Bad Hashes (CSV)...", self)
        act_import_bad.triggered.connect(lambda: self.import_hashes(False))
        tools_menu.addAction(act_import_bad)

        act_export_report = QtGui.QAction("Export Current Report (HTML)...", self)
        act_export_report.setShortcut("Ctrl+Shift+R")
        act_export_report.triggered.connect(self.export_report)
        tools_menu.addAction(act_export_report)

        time_menu = tools_menu.addMenu("Time Display Mode")
        act_time_local = QtGui.QAction("Local time", self, checkable=True)
        act_time_utc = QtGui.QAction("UTC", self, checkable=True)
        act_time_local.setChecked(True)
        time_group = QtGui.QActionGroup(self)
        time_group.addAction(act_time_local)
        time_group.addAction(act_time_utc)
        time_menu.addAction(act_time_local)
        time_menu.addAction(act_time_utc)
        act_time_local.triggered.connect(lambda: self.set_time_mode("local"))
        act_time_utc.triggered.connect(lambda: self.set_time_mode("utc"))

        act_quick_start = QtGui.QAction("Quick Start Guide", self)
        act_quick_start.triggered.connect(self.show_quick_start)
        act_tab_overview = QtGui.QAction("Tab Overview", self)
        act_tab_overview.triggered.connect(self.show_tab_overview)
        act_keyboard = QtGui.QAction("Keyboard Shortcuts", self)
        act_keyboard.triggered.connect(self.show_keyboard_shortcuts)
        act_about = QtGui.QAction("About", self)
        act_about.triggered.connect(self.show_about)
        help_menu.addAction(act_quick_start)
        help_menu.addAction(act_tab_overview)
        help_menu.addAction(act_keyboard)
        help_menu.addSeparator()
        help_menu.addAction(act_about)

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        main_layout = QtWidgets.QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        self.sidebar = QtWidgets.QListWidget()
        self.sidebar.setFixedWidth(220)
        self.sidebar.setStyleSheet("""
            QListWidget { background-color: #0f172a; border: none; outline: none; padding-top: 10px; }
            QListWidget::item { color: #94a3b8; padding: 12px 15px; border-left: 3px solid transparent; }
            QListWidget::item:selected { color: #f8fafc; background-color: #1e293b; border-left: 3px solid #3b82f6; }
            QListWidget::item:hover { background-color: #1e293b; }
        """)
        main_layout.addWidget(self.sidebar)

        content_container = QtWidgets.QWidget()
        content_layout = QtWidgets.QVBoxLayout(content_container)
        content_layout.setContentsMargins(20, 20, 20, 20)
        content_layout.setSpacing(15)

        header_layout = QtWidgets.QHBoxLayout()
        self.page_title = QtWidgets.QLabel("Dashboard")
        self.page_title.setStyleSheet("font-size: 24px; font-weight: bold; color: #f1f5f9;")
        header_layout.addWidget(self.page_title)
        header_layout.addStretch()
        header_layout.addWidget(QtWidgets.QLabel("Current Case:"))
        self.case_combo = QtWidgets.QComboBox()
        self.case_combo.setFixedWidth(200)
        header_layout.addWidget(self.case_combo)

        self.btn_new_case = self._create_icon_button("➕")
        self.btn_rename_case = self._create_icon_button("✏️")
        self.btn_delete_case = self._create_icon_button("🗑️")
        for b in (self.btn_new_case, self.btn_rename_case, self.btn_delete_case):
            b.setFixedSize(32, 32)
            b.setStyleSheet(
                "QPushButton { background: transparent; border: none; } QPushButton:hover { background: #334155; border-radius: 4px; }")
        header_layout.addWidget(self.btn_new_case)
        header_layout.addWidget(self.btn_rename_case)
        header_layout.addWidget(self.btn_delete_case)
        content_layout.addLayout(header_layout)

        self.content_stack = QtWidgets.QStackedWidget()
        content_layout.addWidget(self.content_stack)
        main_layout.addWidget(content_container)

        self.pages = {}

        def add_page(name, widget):
            idx = self.content_stack.addWidget(widget)
            self.pages[name] = idx
            item = QtWidgets.QListWidgetItem(name)
            self.sidebar.addItem(item)

        self._build_home_page()
        add_page("Home", self.home_page)

        overview_tab = QtWidgets.QWidget()
        self._build_overview_page(overview_tab)
        add_page("Evidence Overview", overview_tab)

        metadata_tab = QtWidgets.QWidget()
        self._build_metadata_page(metadata_tab)
        add_page("Metadata", metadata_tab)

        hex_strings_tab = QtWidgets.QWidget()
        self._build_hex_strings_page(hex_strings_tab)
        add_page("Hex & Strings", hex_strings_tab)

        archive_tab = self._build_archive_tab()
        add_page("Archive", archive_tab)

        exe_tab = self._build_exe_tab()
        add_page("Executable Analysis", exe_tab)

        sec_tab = self._build_security_tab()
        add_page("Security Tools", sec_tab)

        brow_tab = self._build_browser_artifacts_tab()
        add_page("Browser Artifacts", brow_tab)

        prev_tab = self._build_preview_tab()
        add_page("Preview", prev_tab)

        comp_tab = self._build_comparisons_tab()
        add_page("Comparisons", comp_tab)

        stego_tab = self._build_stego_tab()
        add_page("Steganography", stego_tab)

        carve_tab = self._build_carving_tab()
        add_page("File Carving", carve_tab)

        adv_tab = self._build_advanced_tab()
        add_page("Advanced Analysis", adv_tab)

        custody_tab = self._build_custody_tab()
        add_page("Chain of Custody", custody_tab)

        timeline_tab = self._build_timeline_tab()
        add_page("Case Timeline", timeline_tab)

        iocs_tab = self._build_iocs_tab()
        add_page("IOC Extraction", iocs_tab)

        self.sidebar.currentRowChanged.connect(self._on_sidebar_changed)
        self.sidebar.setCurrentRow(0)

        self.case_combo.currentIndexChanged.connect(self.change_case)
        self.btn_new_case.clicked.connect(self.create_case_dialog)
        self.btn_rename_case.clicked.connect(self.rename_case_dialog)
        self.btn_delete_case.clicked.connect(self.delete_case_dialog)

    def _create_icon_button(self, text):
        btn = QtWidgets.QPushButton(text)
        font = btn.font()
        font.setPointSize(14)
        btn.setFont(font)
        return btn

    def _on_sidebar_changed(self, row):
        if row < 0:
            return
        self.content_stack.setCurrentIndex(row)
        item = self.sidebar.item(row)
        if item:
            self.page_title.setText(item.text())

    # ------------------------ Page Builders ------------------------
    def _build_home_page(self):
        self.home_page = QtWidgets.QWidget()
        self.home_page.setStyleSheet("background-color: #0f172a;")
        layout = QtWidgets.QVBoxLayout(self.home_page)
        layout.setContentsMargins(0, 0, 0, 0)
        banner = QtWidgets.QLabel("FORENSIX STUDIO")
        banner.setStyleSheet("font-size: 42px; font-weight: 900; color: #3b82f6; letter-spacing: 2px; background: transparent;")
        banner.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(banner)
        subtitle = QtWidgets.QLabel("ADVANCED DIGITAL INVESTIGATION TOOLKIT")
        subtitle.setStyleSheet(
            "font-size: 14px; font-weight: bold; color: #64748b; letter-spacing: 4px; margin-bottom: 40px; background: transparent;")
        subtitle.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(subtitle)
        grid_container = QtWidgets.QWidget()
        grid_container.setStyleSheet("background: transparent;")
        grid = QtWidgets.QGridLayout(grid_container)
        grid.setSpacing(25)

        def make_card(title, desc, func, color="#3b82f6"):
            frame = QtWidgets.QFrame()
            frame.setFixedSize(220, 220)
            frame.setCursor(QtCore.Qt.PointingHandCursor)
            frame.setStyleSheet(f"""
                QFrame {{ background-color: #1e293b; border-radius: 12px; border: 1px solid #334155; }}
                QFrame:hover {{ border: 2px solid {color}; background-color: #253347; }}
            """)
            card_layout = QtWidgets.QVBoxLayout(frame)
            card_layout.setContentsMargins(20, 20, 20, 20)
            icon_lbl = QtWidgets.QLabel("📁")
            icon_lbl.setAlignment(QtCore.Qt.AlignCenter)
            icon_lbl.setStyleSheet("font-size: 48px; border: none; background: transparent;")
            card_layout.addWidget(icon_lbl)
            lbl = QtWidgets.QLabel(title)
            lbl.setAlignment(QtCore.Qt.AlignCenter)
            lbl.setStyleSheet(f"font-size: 18px; font-weight: bold; color: #f8fafc; margin-top: 10px; background: transparent;")
            card_layout.addWidget(lbl)
            desc_lbl = QtWidgets.QLabel(desc)
            desc_lbl.setAlignment(QtCore.Qt.AlignCenter)
            desc_lbl.setWordWrap(True)
            desc_lbl.setStyleSheet("color: #94a3b8; font-size: 12px; background: transparent;")
            card_layout.addWidget(desc_lbl)
            btn = QtWidgets.QPushButton(frame)
            btn.setGeometry(0, 0, 220, 220)
            btn.setStyleSheet("background: transparent; border: none;")
            btn.clicked.connect(func)
            return frame

        grid.addWidget(
            make_card("OPEN EVIDENCE", "Load a target file to begin forensic analysis.", self.choose_file, "#10b981"),
            0, 0)
        grid.addWidget(make_card("DATA CARVING", "Recover deleted files from raw disk images or folders.",
                                 lambda: self.sidebar.setCurrentRow(11), "#f59e0b"), 0, 1)
        grid.addWidget(
            make_card("DIRECTORY SCAN", "Batch process an entire directory structure.", self.directory_scan, "#8b5cf6"),
            0, 2)
        grid.addWidget(
            make_card("COMMAND PALETTE", "Access all tools via keyboard (Ctrl+Shift+P).", self.show_command_palette,
                      "#ef4444"), 0, 3)
        layout.addWidget(grid_container, 0, QtCore.Qt.AlignCenter)
        layout.addStretch()
        footer = QtWidgets.QLabel("v1.0.0 | Secure Forensic Workstation")
        footer.setStyleSheet("color: #475569; font-size: 10px; background: transparent;")
        footer.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(footer)

    def _build_overview_page(self, parent):
        parent.setStyleSheet("background-color: #0f172a;")
        layout = QtWidgets.QVBoxLayout(parent)
        layout.setContentsMargins(0, 0, 0, 0)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        splitter.setHandleWidth(1)
        splitter.setStyleSheet("QSplitter::handle { background-color: #1e293b; }")
        layout.addWidget(splitter)
        left_widget = QtWidgets.QWidget()
        left_widget.setStyleSheet("background-color: #0f172a;")
        left_lay = QtWidgets.QVBoxLayout(left_widget)
        left_lay.setContentsMargins(0, 0, 10, 0)
        left_lay.addWidget(QtWidgets.QLabel("Evidence Files"))
        self.ev_filter_edit = QtWidgets.QLineEdit()
        self.ev_filter_edit.setPlaceholderText("Filter...")
        self.ev_filter_edit.textChanged.connect(self.filter_evidence_list)
        left_lay.addWidget(self.ev_filter_edit)
        self.evidence_list = QtWidgets.QListWidget()
        left_lay.addWidget(self.evidence_list)
        btn_add = QtWidgets.QPushButton("Add File")
        btn_add.clicked.connect(self.choose_file)
        left_lay.addWidget(btn_add)
        self.btn_remove_evidence = QtWidgets.QPushButton("Remove")
        self.btn_remove_evidence.clicked.connect(self.remove_selected_evidence)
        left_lay.addWidget(self.btn_remove_evidence)
        splitter.addWidget(left_widget)

        right_widget = QtWidgets.QWidget()
        right_widget.setStyleSheet("background-color: #0f172a;")
        right_lay = QtWidgets.QVBoxLayout(right_widget)
        right_lay.setContentsMargins(10, 0, 0, 0)

        summary_group = QtWidgets.QGroupBox("🔍 SCAN SUMMARY")
        summary_group.setStyleSheet("""
            QGroupBox { 
                font-weight: bold; 
                color: #f8fafc; 
                border: 1px solid #334155; 
                border-radius: 8px; 
                margin-top: 12px; 
                padding-top: 10px;
                background-color: #0f172a;
            }
            QGroupBox::title { 
                subcontrol-origin: margin; 
                left: 10px; 
                padding: 0 5px;
                color: #94a3b8;
            }
        """)
        summary_layout = QtWidgets.QVBoxLayout(summary_group)

        self.summary_risk_label = QtWidgets.QLabel("Risk Level: N/A")
        self.summary_risk_label.setStyleSheet("""
            font-size: 16px; 
            font-weight: bold; 
            padding: 8px; 
            border-radius: 6px;
            background-color: #1e293b;
        """)
        self.summary_risk_label.setAlignment(QtCore.Qt.AlignCenter)
        summary_layout.addWidget(self.summary_risk_label)

        info_grid = QtWidgets.QGridLayout()
        self.summary_filetype_label = QtWidgets.QLabel("File Type: -")
        self.summary_entropy_label = QtWidgets.QLabel("Entropy: -")
        self.summary_malware_label = QtWidgets.QLabel("Malware Score: -")
        self.summary_ioc_count_label = QtWidgets.QLabel("IOCs: 0")
        info_grid.addWidget(self.summary_filetype_label, 0, 0)
        info_grid.addWidget(self.summary_entropy_label, 0, 1)
        info_grid.addWidget(self.summary_malware_label, 1, 0)
        info_grid.addWidget(self.summary_ioc_count_label, 1, 1)
        summary_layout.addLayout(info_grid)

        self.summary_mismatch_label = QtWidgets.QLabel("")
        self.summary_mismatch_label.setStyleSheet("color: #f97316; font-weight: bold; padding: 4px;")
        self.summary_mismatch_label.setWordWrap(True)
        summary_layout.addWidget(self.summary_mismatch_label)

        self.summary_findings_text = QtWidgets.QTextEdit()
        self.summary_findings_text.setReadOnly(True)
        self.summary_findings_text.setMaximumHeight(100)
        self.summary_findings_text.setStyleSheet("""
            background-color: #1e293b; 
            color: #e2e8f0; 
            border: 1px solid #334155;
            border-radius: 4px;
        """)
        summary_layout.addWidget(self.summary_findings_text)

        self.summary_explanation_label = QtWidgets.QLabel("")
        self.summary_explanation_label.setWordWrap(True)
        self.summary_explanation_label.setStyleSheet("color: #94a3b8; font-style: italic; padding: 4px;")
        summary_layout.addWidget(self.summary_explanation_label)

        right_lay.addWidget(summary_group)

        self.btn_full_analysis = QtWidgets.QPushButton("🚀 Run Full Analysis")
        self.btn_full_analysis.clicked.connect(self.run_full_analysis)
        self.btn_full_analysis.setStyleSheet("""
            QPushButton { 
                background-color: #3b82f6; 
                color: white; 
                font-weight: bold; 
                padding: 10px; 
                border-radius: 6px;
                border: none;
            } 
            QPushButton:hover { background-color: #2563eb; }
        """)
        right_lay.addWidget(self.btn_full_analysis)

        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        info_widget = QtWidgets.QWidget()
        info_widget.setStyleSheet("background-color: #0f172a;")
        info_layout = QtWidgets.QGridLayout(info_widget)

        self.info_labels = {}

        def add_row(r, label_text, key):
            lbl = QtWidgets.QLabel(label_text)
            val = QtWidgets.QLabel("-")
            val.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
            info_layout.addWidget(lbl, r, 0)
            info_layout.addWidget(val, r, 1)
            self.info_labels[key] = val

        row = 0
        add_row(row, "Case ID:", "case_id"); row += 1
        add_row(row, "Evidence ID:", "evidence_id"); row += 1
        add_row(row, "Tags:", "tags"); row += 1
        add_row(row, "File name:", "name"); row += 1
        add_row(row, "Directory:", "directory"); row += 1
        add_row(row, "Size:", "size"); row += 1
        add_row(row, "Created:", "created"); row += 1
        add_row(row, "Modified:", "modified"); row += 1
        add_row(row, "Accessed:", "accessed"); row += 1
        add_row(row, "MIME type:", "mime"); row += 1
        add_row(row, "Extension:", "ext"); row += 1
        add_row(row, "Permissions:", "perms"); row += 1
        add_row(row, "Entropy:", "entropy"); row += 1
        add_row(row, "Malware Score:", "malware_score"); row += 1
        self.entropy_bar = QtWidgets.QProgressBar()
        self.entropy_bar.setRange(0, 800)
        info_layout.addWidget(QtWidgets.QLabel("Entropy Graph:"), row, 0)
        info_layout.addWidget(self.entropy_bar, row, 1); row += 1
        hashes_group = QtWidgets.QGroupBox("Hashes")
        h_lay = QtWidgets.QFormLayout(hashes_group)
        self.hash_edits = {}
        for algo in ["md5", "sha1", "sha256", "sha512"]:
            edit = QtWidgets.QLineEdit()
            edit.setReadOnly(True)
            self.hash_edits[algo] = edit
            h_lay.addRow(algo.upper() + ":", edit)
        info_layout.addWidget(hashes_group, row, 0, 1, 2); row += 1
        self.evidence_note_edit = QtWidgets.QPlainTextEdit()
        self.evidence_note_edit.setPlaceholderText("Notes...")
        self.evidence_note_edit.setMaximumHeight(100)
        info_layout.addWidget(QtWidgets.QLabel("Notes:"), row, 0)
        info_layout.addWidget(self.evidence_note_edit, row, 1); row += 1

        scroll.setWidget(info_widget)
        right_lay.addWidget(scroll)

        splitter.addWidget(right_widget)
        splitter.setStretchFactor(1, 2)
        self.evidence_list.itemDoubleClicked.connect(self._on_evidence_double_clicked)
        self.evidence_list.currentItemChanged.connect(self._on_evidence_selected)

    def _build_metadata_page(self, parent):
        parent.setStyleSheet("background-color: #0f172a;")
        layout = QtWidgets.QVBoxLayout(parent)
        self.metadata_table = QtWidgets.QTableWidget(0, 2)
        self.metadata_table.setHorizontalHeaderLabels(["Key", "Value"])
        self.metadata_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.metadata_table)
        row = QtWidgets.QHBoxLayout()
        self.btn_strip_meta = QtWidgets.QPushButton("Strip Metadata")
        self.btn_save_meta = QtWidgets.QPushButton("Save Edited Metadata")
        row.addWidget(self.btn_strip_meta)
        row.addWidget(self.btn_save_meta)
        layout.addLayout(row)
        self.btn_strip_meta.clicked.connect(self.strip_metadata)
        self.btn_save_meta.clicked.connect(self.save_edited_metadata)

    def _build_hex_strings_page(self, parent):
        parent.setStyleSheet("background-color: #0f172a;")
        layout = QtWidgets.QVBoxLayout(parent)
        tabs = QtWidgets.QTabWidget()
        layout.addWidget(tabs)
        hex_tab = QtWidgets.QWidget()
        hex_lay = QtWidgets.QVBoxLayout(hex_tab)
        row = QtWidgets.QHBoxLayout()
        self.hex_search_edit = QtWidgets.QLineEdit()
        self.hex_search_edit.setPlaceholderText("Search hex...")
        self.btn_hex_search = QtWidgets.QPushButton("Find")
        row.addWidget(self.hex_search_edit)
        row.addWidget(self.btn_hex_search)
        hex_lay.addLayout(row)
        self.hex_view = QtWidgets.QPlainTextEdit()
        self.hex_view.setFont(QtGui.QFont("Courier New", 10))
        self.hex_view.setReadOnly(True)
        hex_lay.addWidget(self.hex_view)
        tabs.addTab(hex_tab, "Hex View")
        str_tab = QtWidgets.QWidget()
        str_lay = QtWidgets.QVBoxLayout(str_tab)
        row2 = QtWidgets.QHBoxLayout()
        self.str_min_len = QtWidgets.QSpinBox()
        self.str_min_len.setValue(4)
        self.chk_ascii = QtWidgets.QCheckBox("ASCII")
        self.chk_ascii.setChecked(True)
        self.chk_unicode = QtWidgets.QCheckBox("UTF-16")
        self.btn_extract_strings = QtWidgets.QPushButton("Extract")
        row2.addWidget(QtWidgets.QLabel("Min Len:"))
        row2.addWidget(self.str_min_len)
        row2.addWidget(self.chk_ascii)
        row2.addWidget(self.chk_unicode)
        row2.addWidget(self.btn_extract_strings)
        str_lay.addLayout(row2)

        filter_row = QtWidgets.QHBoxLayout()
        self.chk_suspicious_only = QtWidgets.QCheckBox("Show only suspicious strings")
        self.btn_apply_filter = QtWidgets.QPushButton("Apply Filter")
        filter_row.addWidget(self.chk_suspicious_only)
        filter_row.addWidget(self.btn_apply_filter)
        filter_row.addStretch()
        str_lay.addLayout(filter_row)

        self.strings_view = QtWidgets.QPlainTextEdit()
        str_lay.addWidget(self.strings_view)
        tabs.addTab(str_tab, "Strings")
        self.btn_hex_search.clicked.connect(self.hex_search)
        self.btn_extract_strings.clicked.connect(self.extract_strings)
        self.btn_apply_filter.clicked.connect(self.apply_strings_filter)

    def _build_archive_tab(self):
        archive_tab = QtWidgets.QWidget()
        archive_tab.setStyleSheet("background-color: #0f172a;")
        arch_layout = QtWidgets.QVBoxLayout(archive_tab)
        self.archive_info_label = QtWidgets.QLabel("No archive loaded.")
        arch_layout.addWidget(self.archive_info_label)
        self.archive_table = QtWidgets.QTableWidget(0, 5)
        self.archive_table.setHorizontalHeaderLabels(["Name", "Size", "Compressed", "Type", "Path"])
        self.archive_table.horizontalHeader().setStretchLastSection(True)
        arch_layout.addWidget(self.archive_table)
        btn_row = QtWidgets.QHBoxLayout()
        self.btn_archive_extract_selected = QtWidgets.QPushButton("Extract Selected…")
        self.btn_archive_extract_add = QtWidgets.QPushButton("Extract Selected + Add as Evidence…")
        self.btn_archive_export_csv = QtWidgets.QPushButton("Export Listing (CSV)…")
        btn_row.addWidget(self.btn_archive_extract_selected)
        btn_row.addWidget(self.btn_archive_extract_add)
        btn_row.addWidget(self.btn_archive_export_csv)
        arch_layout.addLayout(btn_row)
        self.btn_archive_extract_selected.clicked.connect(self.archive_extract_selected)
        self.btn_archive_extract_add.clicked.connect(self.archive_extract_add_evidence)
        self.btn_archive_export_csv.clicked.connect(self.archive_export_csv)
        return archive_tab

    def _build_exe_tab(self):
        exe_tab = QtWidgets.QWidget()
        exe_tab.setStyleSheet("background-color: #0f172a;")
        exe_layout = QtWidgets.QVBoxLayout(exe_tab)
        self.exe_info = QtWidgets.QLabel("")
        self.exe_info.setWordWrap(True)
        exe_layout.addWidget(self.exe_info)
        self.exe_table = QtWidgets.QTableWidget(0, 4)
        self.exe_table.setHorizontalHeaderLabels(["Section", "Virtual Size", "Raw Size", "Entropy"])
        exe_layout.addWidget(self.exe_table)
        yara_row = QtWidgets.QHBoxLayout()
        self.yara_rules_path_edit = QtWidgets.QLineEdit()
        self.yara_rules_path_edit.setPlaceholderText("YARA rules file (.yar / .yara)...")
        self.btn_browse_yara = QtWidgets.QPushButton("Browse")
        self.btn_run_yara = QtWidgets.QPushButton("Run YARA Scan")
        yara_row.addWidget(self.yara_rules_path_edit)
        yara_row.addWidget(self.btn_browse_yara)
        yara_row.addWidget(self.btn_run_yara)
        exe_layout.addLayout(yara_row)
        self.yara_result = QtWidgets.QPlainTextEdit()
        self.yara_result.setReadOnly(True)
        exe_layout.addWidget(self.yara_result)
        self.btn_browse_yara.clicked.connect(self.browse_yara_rules)
        self.btn_run_yara.clicked.connect(self.run_yara_scan)
        return exe_tab

    def _build_security_tab(self):
        sec_tab = QtWidgets.QWidget()
        sec_tab.setStyleSheet("background-color: #0f172a;")
        layout = QtWidgets.QVBoxLayout(sec_tab)
        info = QtWidgets.QLabel("Security Tools: Encrypt/Decrypt (AES-256-GCM), Secure Wipe, PDF Password Protection.")
        info.setWordWrap(True)
        layout.addWidget(info)
        aes_group = QtWidgets.QGroupBox("AES-256-GCM Encryption")
        aes_layout = QtWidgets.QHBoxLayout(aes_group)
        self.btn_encrypt = QtWidgets.QPushButton("Encrypt File…")
        self.btn_decrypt = QtWidgets.QPushButton("Decrypt .enc File…")
        aes_layout.addWidget(self.btn_encrypt)
        aes_layout.addWidget(self.btn_decrypt)
        layout.addWidget(aes_group)
        pdf_group = QtWidgets.QGroupBox("PDF Security")
        pdf_layout = QtWidgets.QHBoxLayout(pdf_group)
        self.btn_pdf_protect = QtWidgets.QPushButton("Add Password to PDF…")
        pdf_layout.addWidget(self.btn_pdf_protect)
        layout.addWidget(pdf_group)
        wipe_group = QtWidgets.QGroupBox("Destruction")
        wipe_layout = QtWidgets.QHBoxLayout(wipe_group)
        self.btn_secure_wipe = QtWidgets.QPushButton("Secure Wipe Current File")
        self.btn_secure_wipe.setStyleSheet("background-color: #7f1d1d; color: white;")
        wipe_layout.addWidget(self.btn_secure_wipe)
        layout.addWidget(wipe_group)
        layout.addStretch()
        self.btn_encrypt.clicked.connect(self.encrypt_current_file)
        self.btn_decrypt.clicked.connect(self.decrypt_file_dialog)
        self.btn_pdf_protect.clicked.connect(self.pdf_add_password)
        self.btn_secure_wipe.clicked.connect(self.secure_wipe_current)
        return sec_tab

    def _build_browser_artifacts_tab(self):
        art_tab = QtWidgets.QWidget()
        art_tab.setStyleSheet("background-color: #0f172a;")
        layout = QtWidgets.QVBoxLayout(art_tab)
        self.artifacts_info_label = QtWidgets.QLabel("No recognized browser artifacts.")
        layout.addWidget(self.artifacts_info_label)
        search_row = QtWidgets.QHBoxLayout()
        self.artifacts_search_edit = QtWidgets.QLineEdit()
        self.artifacts_search_edit.setPlaceholderText("Filter by URL/title…")
        self.btn_artifacts_search = QtWidgets.QPushButton("Filter")
        search_row.addWidget(self.artifacts_search_edit)
        search_row.addWidget(self.btn_artifacts_search)
        layout.addLayout(search_row)
        self.artifacts_table = QtWidgets.QTableWidget(0, 4)
        self.artifacts_table.setHorizontalHeaderLabels(["Time", "URL", "Title", "Visits"])
        self.artifacts_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.artifacts_table)
        self.btn_artifacts_search.clicked.connect(self.filter_artifacts)
        return art_tab

    def _build_preview_tab(self):
        prev_tab = QtWidgets.QWidget()
        prev_tab.setStyleSheet("background-color: #0f172a;")
        layout = QtWidgets.QVBoxLayout(prev_tab)
        self.preview_label = QtWidgets.QLabel("No preview available.")
        self.preview_label.setAlignment(QtCore.Qt.AlignCenter)
        self.preview_label.setMinimumHeight(300)
        self.preview_label.setFrameShape(QtWidgets.QFrame.StyledPanel)
        layout.addWidget(self.preview_label, 1)
        self.preview_info = QtWidgets.QLabel("")
        self.preview_info.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(self.preview_info)
        return prev_tab

    def _build_comparisons_tab(self):
        comp_tab = QtWidgets.QWidget()
        comp_tab.setStyleSheet("background-color: #0f172a;")
        layout = QtWidgets.QVBoxLayout(comp_tab)
        layout.addWidget(QtWidgets.QLabel("Compare the currently loaded file with another file."))
        row = QtWidgets.QHBoxLayout()
        self.btn_select_compare = QtWidgets.QPushButton("Select File to Compare With...")
        self.btn_run_compare = QtWidgets.QPushButton("Run Comparison (Hex/Text)")
        row.addWidget(self.btn_select_compare)
        row.addWidget(self.btn_run_compare)
        layout.addLayout(row)
        self.compare_path_label = QtWidgets.QLabel("No secondary file selected.")
        layout.addWidget(self.compare_path_label)
        self.compare_result = QtWidgets.QPlainTextEdit()
        self.compare_result.setReadOnly(True)
        layout.addWidget(self.compare_result)
        self.btn_select_compare.clicked.connect(self.select_comparison_file)
        self.btn_run_compare.clicked.connect(self.run_comparison)
        self.compare_target_path = None
        return comp_tab

    def _build_stego_tab(self):
        stego_tab = QtWidgets.QWidget()
        stego_tab.setStyleSheet("background-color: #0f172a;")
        layout = QtWidgets.QVBoxLayout(stego_tab)
        layout.addWidget(QtWidgets.QLabel("LSB Steganography (PNG only). Hide or Reveal secrets."))
        tabs = QtWidgets.QTabWidget()
        hide_tab = QtWidgets.QWidget()
        h_layout = QtWidgets.QVBoxLayout(hide_tab)
        self.stego_input_text = QtWidgets.QPlainTextEdit()
        self.stego_input_text.setPlaceholderText("Enter secret message to hide...")
        h_layout.addWidget(self.stego_input_text)
        self.btn_stego_hide = QtWidgets.QPushButton("Embed Text & Save PNG...")
        self.btn_stego_hide.clicked.connect(self.stego_embed)
        h_layout.addWidget(self.btn_stego_hide)
        tabs.addTab(hide_tab, "Hide")
        reveal_tab = QtWidgets.QWidget()
        r_layout = QtWidgets.QVBoxLayout(reveal_tab)
        self.btn_stego_reveal = QtWidgets.QPushButton("Reveal Text from Current PNG")
        self.btn_stego_reveal.clicked.connect(self.stego_extract)
        r_layout.addWidget(self.btn_stego_reveal)
        self.stego_output_text = QtWidgets.QPlainTextEdit()
        self.stego_output_text.setReadOnly(True)
        r_layout.addWidget(self.stego_output_text)
        tabs.addTab(reveal_tab, "Reveal")
        layout.addWidget(tabs)
        return stego_tab

    def _build_carving_tab(self):
        carve_tab = QtWidgets.QWidget()
        carve_tab.setStyleSheet("background-color: #0f172a;")
        layout = QtWidgets.QVBoxLayout(carve_tab)
        info = QtWidgets.QLabel("File Carving: Scan a DIRECTORY for deleted or embedded files.")
        info.setWordWrap(True)
        layout.addWidget(info)
        self.btn_run_carve = QtWidgets.QPushButton("Select Directory to Carve...")
        self.btn_run_carve.clicked.connect(self.run_carving)
        layout.addWidget(self.btn_run_carve)
        self.carve_log = QtWidgets.QPlainTextEdit()
        self.carve_log.setReadOnly(True)
        layout.addWidget(self.carve_log)
        return carve_tab

    def _build_advanced_tab(self):
        adv_tab = QtWidgets.QWidget()
        adv_tab.setStyleSheet("background-color: #0f172a;")
        layout = QtWidgets.QVBoxLayout(adv_tab)
        grp_mal = QtWidgets.QGroupBox("Malware Analysis")
        l_mal = QtWidgets.QVBoxLayout(grp_mal)
        self.btn_malware_scan = QtWidgets.QPushButton("Identify Malware Indicators (Heuristic)")
        self.btn_malware_scan.clicked.connect(self.run_malware_scan)
        l_mal.addWidget(self.btn_malware_scan)
        self.malware_result = QtWidgets.QLabel("Not scanned.")
        self.malware_result.setWordWrap(True)
        l_mal.addWidget(self.malware_result)
        layout.addWidget(grp_mal)
        grp_mac = QtWidgets.QGroupBox("Macros / Scripts")
        l_mac = QtWidgets.QVBoxLayout(grp_mac)
        self.btn_scan_macros = QtWidgets.QPushButton("Scan for Macros/Scripts")
        self.btn_scan_macros.clicked.connect(self.scan_macros)
        l_mac.addWidget(self.btn_scan_macros)
        self.macro_result = QtWidgets.QLabel("-")
        l_mac.addWidget(self.macro_result)
        layout.addWidget(grp_mac)
        grp_emb = QtWidgets.QGroupBox("Embedded Object Detector")
        l_emb = QtWidgets.QVBoxLayout(grp_emb)
        self.btn_scan_embedded = QtWidgets.QPushButton("Scan for Embedded Objects (OLE/PDF)")
        self.btn_scan_embedded.clicked.connect(self.scan_embedded)
        l_emb.addWidget(self.btn_scan_embedded)
        self.embedded_result = QtWidgets.QPlainTextEdit()
        self.embedded_result.setMaximumHeight(100)
        l_emb.addWidget(self.embedded_result)
        layout.addWidget(grp_emb)
        layout.addStretch()
        return adv_tab

    def _build_custody_tab(self):
        w = QtWidgets.QWidget()
        w.setStyleSheet("background-color: #0f172a;")
        l = QtWidgets.QVBoxLayout(w)
        self.chain_view = QtWidgets.QPlainTextEdit()
        self.chain_view.setReadOnly(True)
        l.addWidget(self.chain_view)
        return w

    def _build_timeline_tab(self):
        w = QtWidgets.QWidget()
        w.setStyleSheet("background-color: #0f172a;")
        l = QtWidgets.QVBoxLayout(w)
        self.timeline_view = QtWidgets.QPlainTextEdit()
        self.timeline_view.setReadOnly(True)
        l.addWidget(self.timeline_view)
        return w

    def _build_iocs_tab(self):
        w = QtWidgets.QWidget()
        w.setStyleSheet("background-color: #0f172a;")
        l = QtWidgets.QVBoxLayout(w)
        self.btn_extract_iocs = QtWidgets.QPushButton("Extract IOCs from Current File")
        self.btn_extract_iocs.clicked.connect(self.extract_and_display_iocs)
        l.addWidget(self.btn_extract_iocs)
        self.iocs_text = QtWidgets.QPlainTextEdit()
        self.iocs_text.setReadOnly(True)
        l.addWidget(self.iocs_text)
        return w

    # ------------------------ Style ------------------------
    def _apply_style(self):
        palette = self.palette()
        if self.dark_mode:
            palette.setColor(QtGui.QPalette.Window, QtGui.QColor("#0f172a"))
            palette.setColor(QtGui.QPalette.WindowText, QtGui.QColor("#e5e7eb"))
            palette.setColor(QtGui.QPalette.Base, QtGui.QColor("#0f172a"))
            palette.setColor(QtGui.QPalette.AlternateBase, QtGui.QColor("#1e293b"))
            palette.setColor(QtGui.QPalette.Text, QtGui.QColor("#e5e7eb"))
            palette.setColor(QtGui.QPalette.Button, QtGui.QColor("#1e293b"))
            palette.setColor(QtGui.QPalette.ButtonText, QtGui.QColor("#e5e7eb"))
            palette.setColor(QtGui.QPalette.Highlight, QtGui.QColor("#3b82f6"))
        else:
            palette.setColor(QtGui.QPalette.Window, QtGui.QColor("#f8fafc"))
            palette.setColor(QtGui.QPalette.WindowText, QtGui.QColor("#0f172a"))
            palette.setColor(QtGui.QPalette.Base, QtGui.QColor("#ffffff"))
            palette.setColor(QtGui.QPalette.AlternateBase, QtGui.QColor("#f1f5f9"))
            palette.setColor(QtGui.QPalette.Text, QtGui.QColor("#0f172a"))
            palette.setColor(QtGui.QPalette.Button, QtGui.QColor("#e2e8f0"))
            palette.setColor(QtGui.QPalette.ButtonText, QtGui.QColor("#0f172a"))
            palette.setColor(QtGui.QPalette.Highlight, QtGui.QColor("#2563eb"))
        self.setPalette(palette)
        self.setStyleSheet("""
            QMainWindow { background-color: #0f172a; }
            QWidget { background-color: #0f172a; }
            QSplitter::handle { background-color: #1e293b; width: 1px; }
            QScrollArea { border: none; background-color: transparent; }
            QScrollBar:vertical { background: #0f172a; width: 10px; }
            QScrollBar::handle:vertical { background: #334155; border-radius: 5px; min-height: 20px; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { border: none; background: none; }
            QLabel { color: #e2e8f0; }
            QListWidget { border-radius: 6px; border: 1px solid #1f2937; background-color: #0f172a; color: #e2e8f0; }
            QLineEdit, QTextEdit, QPlainTextEdit, QTableWidget, QSpinBox, QComboBox {
                border-radius: 6px; border: 1px solid #1f2937; background-color: #1e293b; color: #e2e8f0;
            }
            QGroupBox { 
                border: 1px solid #1f2937; 
                border-radius: 8px; 
                margin-top: 12px; 
                padding: 6px;
                background-color: #0f172a;
            }
            QGroupBox::title { 
                subcontrol-origin: margin; 
                left: 10px; 
                padding: 0 5px; 
                color: #9ca3af;
                background-color: #0f172a;
            }
            QPushButton { border-radius: 6px; padding: 6px 12px; border: 1px solid #1f2937; background-color: #1e293b; color: #e2e8f0; }
            QPushButton:hover { border-color: #38bdf8; }
            QTabWidget::pane { border: 1px solid #1f2937; border-radius: 8px; background: #0f172a; }
            QTabBar::tab { background: #0f172a; color: #9ca3af; padding: 6px 12px; }
            QTabBar::tab:selected { background: #1e293b; color: #f8fafc; }
            QMenuBar { background-color: #0f172a; color: #e2e8f0; }
            QMenuBar::item:selected { background-color: #1e293b; }
            QMenu { background-color: #0f172a; color: #e2e8f0; }
            QMenu::item:selected { background-color: #1e293b; }
            QHeaderView::section { background-color: #0f172a; color: #9ca3af; border: 1px solid #1f2937; }
        """)

    def toggle_dark_mode(self):
        self.dark_mode = not self.dark_mode
        self._apply_style()
        self.statusBar().showMessage(f"Switched to {'Dark' if self.dark_mode else 'Light'} mode.")

    # ------------------------ Case Management ------------------------
    def _create_default_case(self):
        cid = self._new_case_id()
        self.cases[cid] = {"name": "Case 01", "notes": "", "evidences": set()}
        self.current_case_id = cid
        self._refresh_case_combo()
        self.case_combo.setCurrentIndex(0)
        self.populate_evidence_list()

    def _new_case_id(self) -> str:
        cid = f"CASE{self.case_counter:02d}"
        self.case_counter += 1
        return cid

    def _refresh_case_combo(self):
        self.case_combo.blockSignals(True)
        self.case_combo.clear()
        for cid, c in self.cases.items():
            self.case_combo.addItem(c["name"], cid)
        if self.current_case_id in self.cases:
            idx = list(self.cases.keys()).index(self.current_case_id)
            self.case_combo.setCurrentIndex(idx)
        self.case_combo.blockSignals(False)

    def change_case(self, index):
        if index < 0:
            return
        cid = self.case_combo.itemData(index)
        if not cid or cid not in self.cases:
            return
        self.current_case_id = cid
        self.populate_evidence_list()
        self.current_path = None
        self.clear_all_tabs()
        self.update_dashboard()
        self.update_timeline()
        self.statusBar().showMessage(f"Switched to case: {self.cases[cid]['name']}")

    def create_case_dialog(self):
        name, ok = QtWidgets.QInputDialog.getText(self, "New Case", "Case name:")
        if not ok or not name.strip():
            return
        cid = self._new_case_id()
        self.cases[cid] = {"name": name.strip(), "notes": "", "evidences": set()}
        self.current_case_id = cid
        self._refresh_case_combo()
        self.populate_evidence_list()
        self.update_dashboard()
        self.update_timeline()
        self._log_event(None, f"Case created: {name}")

    def rename_case_dialog(self):
        if not self.current_case_id:
            return
        current = self.cases[self.current_case_id]["name"]
        name, ok = QtWidgets.QInputDialog.getText(self, "Rename Case", "New case name:", text=current)
        if ok and name.strip():
            self.cases[self.current_case_id]["name"] = name.strip()
            self._refresh_case_combo()
            self.update_dashboard()
            self.update_timeline()

    def delete_case_dialog(self):
        if not self.current_case_id or len(self.cases) <= 1:
            QtWidgets.QMessageBox.information(self, "Cannot delete", "At least one case must exist.")
            return
        reply = QtWidgets.QMessageBox.warning(self, "Delete Case", "Delete this case and its evidence references?",
                                              QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
        if reply != QtWidgets.QMessageBox.Yes:
            return
        for path in self.cases[self.current_case_id]["evidences"]:
            if path in self.evidence_db:
                self.evidence_db[path]["case_id"] = None
        del self.cases[self.current_case_id]
        self.current_case_id = next(iter(self.cases.keys()))
        self._refresh_case_combo()
        self.populate_evidence_list()
        self.update_dashboard()
        self.update_timeline()

    # ------------------------ Evidence Management ------------------------
    def populate_evidence_list(self):
        self.evidence_list.clear()
        if not self.current_case_id:
            return
        for path in sorted(self.cases[self.current_case_id]["evidences"]):
            item = QtWidgets.QListWidgetItem(os.path.basename(path))
            item.setToolTip(path)
            item.setData(QtCore.Qt.UserRole, path)
            self.evidence_list.addItem(item)

    def filter_evidence_list(self, text):
        text = text.lower()
        for i in range(self.evidence_list.count()):
            item = self.evidence_list.item(i)
            item.setHidden(text not in item.text().lower())

    def remove_selected_evidence(self):
        item = self.evidence_list.currentItem()
        if not item:
            return
        path = item.data(QtCore.Qt.UserRole)
        if not path:
            return
        reply = QtWidgets.QMessageBox.warning(self, "Remove Evidence", f"Remove from case?\n{path}",
                                              QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
        if reply != QtWidgets.QMessageBox.Yes:
            return
        self.cases[self.current_case_id]["evidences"].discard(path)
        if path in self.evidence_db and self.evidence_db[path]["case_id"] == self.current_case_id:
            self.evidence_db[path]["case_id"] = None
        self.populate_evidence_list()
        if self.current_path == path:
            self.current_path = None
            self.clear_all_tabs()
        self.update_dashboard()
        self.update_timeline()

    def _on_evidence_double_clicked(self, item):
        path = item.data(QtCore.Qt.UserRole)
        if path and os.path.isfile(path):
            self.load_file(path)

    def _on_evidence_selected(self, current, previous):
        if current:
            path = current.data(QtCore.Qt.UserRole)
            if path and os.path.isfile(path) and path != self.current_path:
                self.load_file(path)

    def _ensure_evidence_entry(self, path: str) -> Dict:
        if path in self.evidence_db:
            entry = self.evidence_db[path]
            entry.setdefault("evidence_id", self._new_evidence_id())
            entry.setdefault("tags", set())
            entry.setdefault("note", "")
            entry.setdefault("events", [])
            return entry
        ev_id = self._new_evidence_id()
        entry = {
            "case_id": self.current_case_id,
            "evidence_id": ev_id,
            "baseline_hashes": None,
            "events": [],
            "tags": set(),
            "note": "",
        }
        self.evidence_db[path] = entry
        self._log_event(path, "Evidence registered")
        return entry

    def _new_evidence_id(self) -> str:
        eid = f"EV{self.evidence_counter:04d}"
        self.evidence_counter += 1
        return eid

    def _log_event(self, path: Optional[str], action: str):
        timestamp = datetime.datetime.now().isoformat()
        if path is None:
            record = f"{timestamp} - [CASE] {action}"
        else:
            record = f"{timestamp} - [{os.path.basename(path)}] {action}"
        if path and path in self.evidence_db:
            self.evidence_db[path]["events"].append((timestamp, action))
        self.update_timeline()
        if path == self.current_path:
            self.populate_chain_of_custody()

    # ------------------------ File Loading ------------------------
    def choose_file(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select a file to add as evidence", "", "All Files (*)")
        if path:
            self.add_evidence_from_path(path)

    def add_evidence_from_path(self, path: str):
        if not os.path.isfile(path):
            QtWidgets.QMessageBox.warning(self, "Error", "File does not exist.")
            return
        if not self.current_case_id:
            QtWidgets.QMessageBox.warning(self, "No case", "Create or select a case first.")
            return
        self.cases[self.current_case_id]["evidences"].add(path)
        self._ensure_evidence_entry(path)
        self.populate_evidence_list()
        self.load_file(path)
        self.update_dashboard()
        self.update_timeline()

    def load_file(self, path: str):
        if not os.path.isfile(path):
            QtWidgets.QMessageBox.warning(self, "Error", "File does not exist.")
            return
        self.current_path = path
        self.current_mime = mimetypes.guess_type(path)[0] or "unknown"
        ev = self._ensure_evidence_entry(path)
        self.populate_overview()
        self.populate_hashes(ev)
        self.populate_metadata()
        self.populate_preview()
        self.populate_hex()
        self.populate_exe_tab()
        self.populate_chain_of_custody()
        self.extract_strings(False)
        self.populate_archive_tab()
        self.populate_artifacts_tab()
        self.evidence_note_edit.blockSignals(True)
        self.evidence_note_edit.setPlainText(ev.get("note", ""))
        self.evidence_note_edit.blockSignals(False)

        self.update_scan_summary(None)
        self.last_iocs = {}
        self.iocs_text.clear()

        self.sidebar.setCurrentRow(1)
        self.statusBar().showMessage(f"Loaded: {os.path.basename(path)}")

    # ------------------------ Scan Summary & Risk ------------------------
    def _get_risk_level(self, malware_score: int, entropy: float) -> str:
        if malware_score >= 70 or entropy > 7.5:
            return "MALICIOUS"
        elif malware_score >= 30 or entropy > 6.8:
            return "SUSPICIOUS"
        else:
            return "SAFE"

    def update_scan_summary(self, analysis_data: dict = None):
        if not self.current_path:
            self.summary_risk_label.setText("Risk Level: N/A")
            self.summary_risk_label.setStyleSheet("font-size: 16px; font-weight: bold; padding: 8px; border-radius: 6px; background-color: #1e293b;")
            self.summary_filetype_label.setText("File Type: -")
            self.summary_mismatch_label.setText("")
            self.summary_entropy_label.setText("Entropy: -")
            self.summary_malware_label.setText("Malware Score: -")
            self.summary_ioc_count_label.setText("IOCs: 0")
            self.summary_findings_text.setPlainText("")
            self.summary_explanation_label.setText("")
            return

        if analysis_data:
            analysis = analysis_data.get('analysis', {})
            iocs = analysis_data.get('iocs', {})
            entropy = analysis_data.get('entropy', 0.0)
            malware_score = analysis_data.get('malware_score', 0)
            magic_desc = analysis_data.get('magic_desc', 'Unknown')
            mismatch = analysis_data.get('file_mismatch', {})

            risk = analysis.get('classification', 'SAFE')
            color = analysis.get('color', '#22c55e')
            self.summary_risk_label.setText(f"Risk Level: {risk} ({analysis.get('risk_score', 0)}/100)")
            self.summary_risk_label.setStyleSheet(f"font-size: 16px; font-weight: bold; padding: 8px; border-radius: 6px; background-color: {color}22; color: {color}; border: 1px solid {color};")

            self.summary_filetype_label.setText(f"File Type: {magic_desc}")
            entropy_class = "LOW" if entropy < 3.5 else ("MEDIUM" if entropy < 7.0 else "HIGH")
            self.summary_entropy_label.setText(f"Entropy: {entropy:.3f} ({entropy_class})")
            self.summary_malware_label.setText(f"Malware Score: {malware_score}/100")

            total_iocs = iocs.get('total_iocs', 0)
            self.summary_ioc_count_label.setText(f"IOCs: {total_iocs} (IPs:{len(iocs.get('ips',[]))}, URLs:{len(iocs.get('urls',[]))})")

            if mismatch.get('is_mismatch'):
                self.summary_mismatch_label.setText(f"⚠️ {mismatch.get('explanation', 'File type mismatch')}")
            else:
                self.summary_mismatch_label.setText("")

            findings = analysis.get('findings', [])
            self.summary_findings_text.setPlainText("\n".join(f"• {f}" for f in findings[:5]) if findings else "No significant findings.")
            self.summary_explanation_label.setText(analysis.get('explanation', ''))
        else:
            magic = file_magic(self.current_path, 8)
            magic_desc = detect_magic_label(magic)
            ext = os.path.splitext(self.current_path)[1].lower()
            self.summary_filetype_label.setText(f"File Type: {magic_desc} (ext: {ext})")

            entropy = estimate_entropy(self.current_path)
            entropy_class = "LOW" if entropy < 3.5 else ("MEDIUM" if entropy < 7.0 else "HIGH")
            self.summary_entropy_label.setText(f"Entropy: {entropy:.3f} ({entropy_class})")

            mime = self.current_mime or "unknown"
            mismatch = FileMismatchDetector.detect(self.current_path, mime)
            if mismatch['is_mismatch']:
                self.summary_mismatch_label.setText(f"⚠️ {mismatch['explanation']}")
            else:
                self.summary_mismatch_label.setText("")

            malware_res = MalwareScorer.score_file(self.current_path, entropy, magic_desc, self.known_bad)
            score = malware_res["score"]
            self.summary_malware_label.setText(f"Malware Score: {score}/100")
            if "malware_score" in self.info_labels:
                self.info_labels["malware_score"].setText(str(score))

            self.summary_ioc_count_label.setText("IOCs: (run analysis)")
            self.summary_findings_text.setPlainText("\n".join(f"• {r}" for r in malware_res["reasons"][:3]) if malware_res["reasons"] else "")
            self.summary_explanation_label.setText("Run 'Full Analysis' for complete assessment.")

            risk = self._get_risk_level(score, entropy)
            color = {"SAFE": "#22c55e", "SUSPICIOUS": "#f97316", "MALICIOUS": "#ef4444"}.get(risk, "white")
            self.summary_risk_label.setText(f"Risk Level: {risk}")
            self.summary_risk_label.setStyleSheet(f"font-size: 16px; font-weight: bold; padding: 8px; border-radius: 6px; background-color: {color}22; color: {color}; border: 1px solid {color};")

    # ------------------------ Overview & Hashes ------------------------
    def populate_overview(self):
        if not self.current_path:
            return
        path = self.current_path
        name = os.path.basename(path)
        directory = os.path.dirname(path)
        size = os.path.getsize(path)
        (c_str, _), (m_str, _), (a_str, _) = file_times(path, self.time_mode)
        ext = os.path.splitext(path)[1] or "(none)"
        perms = file_permissions(path)
        entropy = estimate_entropy(path)
        magic = file_magic(path, 8)
        magic_desc = detect_magic_label(magic)
        ev = self._ensure_evidence_entry(path)
        tags_text = ", ".join(sorted(ev["tags"])) if ev["tags"] else "(none)"
        self.info_labels["case_id"].setText(ev["case_id"] or "(no case)")
        self.info_labels["evidence_id"].setText(ev["evidence_id"])
        self.info_labels["tags"].setText(tags_text)
        self.info_labels["name"].setText(name)
        self.info_labels["directory"].setText(directory)
        self.info_labels["size"].setText(f"{size} bytes ({human_size(size)})")
        self.info_labels["created"].setText(c_str)
        self.info_labels["modified"].setText(m_str)
        self.info_labels["accessed"].setText(a_str)
        self.info_labels["mime"].setText(self.current_mime or "unknown")
        self.info_labels["ext"].setText(ext)
        self.info_labels["perms"].setText(perms)
        self.info_labels["entropy"].setText(f"{entropy:.3f}")
        val = int(min(8.0, max(0.0, entropy)) * 100)
        self.entropy_bar.setValue(val)
        if entropy < 3.5:
            self.entropy_bar.setStyleSheet("QProgressBar::chunk { background-color: #22c55e; }")
        elif entropy < 7.0:
            self.entropy_bar.setStyleSheet("QProgressBar::chunk { background-color: #eab308; }")
        else:
            self.entropy_bar.setStyleSheet("QProgressBar::chunk { background-color: #ef4444; }")

        self.update_scan_summary(None)

    def populate_hashes(self, evidence_entry):
        if not self.current_path:
            return
        hashes = compute_hashes(self.current_path, ["md5", "sha1", "sha256", "sha512"])
        for algo, val in hashes.items():
            self.hash_edits[algo].setText(val)
        if evidence_entry["baseline_hashes"] is None:
            evidence_entry["baseline_hashes"] = hashes
            self._log_event(self.current_path, "Baseline hashes computed")
        else:
            self._log_event(self.current_path, "Hashes recomputed")
        sha256 = hashes["sha256"]
        if sha256 in self.known_bad:
            self.statusBar().showMessage("WARNING: Hash matches known-bad set.")
        elif sha256 in self.known_good:
            self.statusBar().showMessage("Info: Hash matches known-good set.")

    def reverify_hashes(self):
        if self.current_path:
            ev = self._ensure_evidence_entry(self.current_path)
            self.populate_hashes(ev)
            QtWidgets.QMessageBox.information(self, "Reverify", "Hashes recomputed.")

    # ------------------------ Metadata ------------------------
    def clear_metadata_table(self):
        self.metadata_table.setRowCount(0)

    def add_metadata_row(self, key, value):
        row = self.metadata_table.rowCount()
        self.metadata_table.insertRow(row)
        self.metadata_table.setItem(row, 0, QtWidgets.QTableWidgetItem(str(key)))
        self.metadata_table.setItem(row, 1, QtWidgets.QTableWidgetItem(str(value)))

    def populate_metadata(self):
        self.clear_metadata_table()
        self.btn_strip_meta.setEnabled(False)
        self.btn_save_meta.setEnabled(False)
        if not self.current_path:
            return
        mime = self.current_mime or ""
        ext = (os.path.splitext(self.current_path)[1] or "").lower()
        if PIL_AVAILABLE and mime.startswith("image"):
            try:
                img = Image.open(self.current_path)
                self.add_metadata_row("Type", f"Image ({img.format})")
                self.add_metadata_row("Size", f"{img.width} x {img.height}")
                self.add_metadata_row("Mode", img.mode)
                exif = img.getexif()
                if exif:
                    self.add_metadata_row("---", "--- EXIF ---")
                    for tag_id, val in exif.items():
                        tag = ExifTags.TAGS.get(tag_id, str(tag_id))
                        self.add_metadata_row(tag, val)
                self.btn_strip_meta.setEnabled(True)
            except Exception as e:
                self.add_metadata_row("Error", f"Failed: {e}")
        elif PYPDF_AVAILABLE and (mime == "application/pdf" or ext == ".pdf"):
            try:
                reader = PdfReader(self.current_path)
                self.add_metadata_row("Type", "PDF document")
                self.add_metadata_row("Pages", len(reader.pages))
                info = reader.metadata or {}
                if info:
                    self.add_metadata_row("---", "--- PDF Info ---")
                    for k, v in info.items():
                        self.add_metadata_row(k, v)
                self.btn_strip_meta.setEnabled(True)
                self.btn_save_meta.setEnabled(True)
            except Exception as e:
                self.add_metadata_row("Error", f"Failed: {e}")
        elif MUTAGEN_AVAILABLE and mime.startswith("audio"):
            try:
                audio = MutagenFile(self.current_path)
                if audio is None:
                    self.add_metadata_row("Info", "Audio type not recognized.")
                else:
                    self.add_metadata_row("Type", "Audio")
                    self.add_metadata_row("Length (s)", getattr(audio.info, "length", ""))
                    if audio.tags:
                        self.add_metadata_row("---", "--- Tags ---")
                        for k, v in audio.tags.items():
                            self.add_metadata_row(k, str(v))
                    self.btn_strip_meta.setEnabled(True)
            except Exception as e:
                self.add_metadata_row("Error", f"Failed: {e}")
        else:
            self.add_metadata_row("Info", "No specialized metadata handler.")

    def strip_metadata(self):
        if not self.current_path:
            return
        mime = self.current_mime or ""
        ext = (os.path.splitext(self.current_path)[1] or "").lower()
        if PIL_AVAILABLE and mime.startswith("image"):
            self.strip_image_metadata()
        elif PYPDF_AVAILABLE and (mime == "application/pdf" or ext == ".pdf"):
            self.strip_pdf_metadata()
        elif MUTAGEN_AVAILABLE and mime.startswith("audio"):
            self.strip_audio_metadata()
        else:
            QtWidgets.QMessageBox.information(self, "Not supported", "Metadata stripping not supported.")

    def strip_image_metadata(self):
        try:
            img = Image.open(self.current_path)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Open failed: {e}")
            return
        dst, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save image without EXIF",
                                                       self._suggest_copy_name("_no_exif"),
                                                       "Images (*.png *.jpg *.jpeg);;All Files (*)")
        if not dst:
            return
        try:
            data = list(img.getdata())
            new_img = Image.new(img.mode, img.size)
            new_img.putdata(data)
            fmt = img.format or None
            new_img.save(dst, format=fmt)
            QtWidgets.QMessageBox.information(self, "Done", "Saved image without EXIF.")
            self._log_event(self.current_path, f"EXIF-stripped copy saved to {dst}")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Strip failed: {e}")

    def strip_pdf_metadata(self):
        if not PYPDF_AVAILABLE:
            return
        try:
            reader = PdfReader(self.current_path)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Open PDF failed: {e}")
            return
        dst, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save PDF without metadata",
                                                       self._suggest_copy_name("_no_meta"),
                                                       "PDF files (*.pdf);;All Files (*)")
        if not dst:
            return
        try:
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            writer.add_metadata({})
            with open(dst, "wb") as f:
                writer.write(f)
            QtWidgets.QMessageBox.information(self, "Done", "Saved PDF without metadata.")
            self._log_event(self.current_path, f"PDF metadata-stripped copy saved to {dst}")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Write failed: {e}")

    def strip_audio_metadata(self):
        if not MUTAGEN_AVAILABLE:
            return
        if self.evidence_mode:
            QtWidgets.QMessageBox.information(self, "Evidence Mode", "Disable Evidence Mode to modify original.")
            return
        reply = QtWidgets.QMessageBox.warning(self, "Delete tags",
                                              "This will remove tags from the original file. Continue?",
                                              QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
        if reply != QtWidgets.QMessageBox.Yes:
            return
        try:
            audio = MutagenFile(self.current_path)
            if audio is None:
                raise ValueError("Unsupported format")
            audio.delete()
            audio.save()
            QtWidgets.QMessageBox.information(self, "Done", "Audio tags removed.")
            self._log_event(self.current_path, "Audio tags removed in-place")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed: {e}")

    def save_edited_metadata(self):
        if not self.current_path:
            return
        mime = self.current_mime or ""
        ext = (os.path.splitext(self.current_path)[1] or "").lower()
        if PYPDF_AVAILABLE and (mime == "application/pdf" or ext == ".pdf"):
            self.save_pdf_metadata_from_table()
        else:
            QtWidgets.QMessageBox.information(self, "Not supported", "Saving metadata only for PDFs.")

    def save_pdf_metadata_from_table(self):
        meta_dict = {}
        for row in range(self.metadata_table.rowCount()):
            k_item = self.metadata_table.item(row, 0)
            v_item = self.metadata_table.item(row, 1)
            if not k_item or not v_item:
                continue
            k = k_item.text().strip()
            v = v_item.text()
            if not k or k.startswith("---") or k in ("Type", "Pages"):
                continue
            if not k.startswith("/"):
                k = "/" + k.replace(" ", "")
            meta_dict[k] = v
        dst, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save PDF with edited metadata",
                                                       self._suggest_copy_name("_edited_meta"),
                                                       "PDF files (*.pdf);;All Files (*)")
        if not dst:
            return
        try:
            reader = PdfReader(self.current_path)
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            writer.add_metadata(meta_dict)
            with open(dst, "wb") as f:
                writer.write(f)
            QtWidgets.QMessageBox.information(self, "Done", "Saved PDF with updated metadata.")
            self._log_event(self.current_path, f"PDF metadata-edited copy saved to {dst}")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed: {e}")

    def _suggest_copy_name(self, suffix):
        if not self.current_path:
            return ""
        base, ext = os.path.splitext(self.current_path)
        return f"{base}{suffix}{ext}"

    # ------------------------ Preview ------------------------
    def populate_preview(self):
        self.preview_label.clear()
        self.preview_info.clear()
        if not self.current_path:
            self.preview_label.setText("No preview available.")
            return
        
        mime = self.current_mime or ""
        ext = (os.path.splitext(self.current_path)[1] or "").lower()
        
        # 1. Image Preview
        if mime.startswith("image") and PIL_AVAILABLE:
            try:
                pix = QtGui.QPixmap(self.current_path)
                if not pix.isNull():
                    scaled = pix.scaled(self.preview_label.size(), QtCore.Qt.KeepAspectRatio,
                                        QtCore.Qt.SmoothTransformation)
                    self.preview_label.setPixmap(scaled)
                    self.preview_info.setText(f"Image Preview: {os.path.basename(self.current_path)}")
                    return
            except Exception:
                pass

        # 2. PDF Preview (Text Extraction)
        if ext == ".pdf" and PYPDF_AVAILABLE:
            try:
                reader = PdfReader(self.current_path)
                first_page = reader.pages[0].extract_text()
                if first_page:
                    self.preview_label.setText(first_page[:4000])
                    self.preview_label.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignLeft)
                    self.preview_info.setText(f"PDF Preview (Page 1 Text) - Total Pages: {len(reader.pages)}")
                    return
            except Exception as e:
                logger.warning(f"PDF preview failed: {e}")

        # 3. Text Preview
        if mime.startswith("text") or ext in (".txt", ".log", ".json", ".py", ".js", ".html", ".css", ".xml", ".csv"):
            try:
                with open(self.current_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read(4000)
                self.preview_label.setText(content)
                self.preview_label.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignLeft)
                self.preview_info.setText("Text preview (first 4 KB)")
                return
            except Exception:
                pass

        # 4. Binary/Hex Fallback Preview
        try:
            with open(self.current_path, "rb") as f:
                data = f.read(512)
            hex_lines = []
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_str = " ".join(f"{b:02x}" for b in chunk)
                printable = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                hex_lines.append(f"{i:08x}:  {hex_str:<48}  |{printable}|")
            
            self.preview_label.setText("\n".join(hex_lines))
            self.preview_label.setStyleSheet("font-family: 'Consolas', 'Courier New', monospace; font-size: 11px; color: #94a3b8;")
            self.preview_label.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignLeft)
            self.preview_info.setText(f"Hex Fallback Preview (MIME: {mime or 'unknown'})")
        except Exception as e:
            self.preview_label.setText(f"Preview failed: {e}")

    # ------------------------ Hex & Strings ------------------------
    def populate_hex(self, max_bytes=4096):
        self.hex_view.clear()
        if not self.current_path:
            return
        try:
            with open(self.current_path, "rb") as f:
                data = f.read(max_bytes)
        except Exception as e:
            self.hex_view.setPlainText(f"Failed: {e}")
            return
        lines = []
        for offset in range(0, len(data), 16):
            chunk = data[offset:offset + 16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{offset:08X}  {hex_part:<48}  {ascii_part}")
        self.hex_view.setPlainText("\n".join(lines))

    def hex_search(self):
        text = self.hex_search_edit.text().strip()
        if not text:
            return
        doc = self.hex_view.document()
        cursor = self.hex_view.textCursor()
        found = doc.find(text, cursor.position())
        if found.isNull():
            found = doc.find(text, 0)
        if not found.isNull():
            self.hex_view.setTextCursor(found)
            self.statusBar().showMessage(f"Found '{text}'")
        else:
            self.statusBar().showMessage(f"'{text}' not found.")

    def extract_strings(self, from_extract=True):
        if not self.current_path:
            return
        if not from_extract:
            self.strings_view.clear()
            self.last_extracted_strings = []
            return
        min_len = self.str_min_len.value()
        ascii_ok = self.chk_ascii.isChecked()
        u16_ok = self.chk_unicode.isChecked()
        if not ascii_ok and not u16_ok:
            QtWidgets.QMessageBox.information(self, "No encodings", "Select at least one encoding.")
            return
        try:
            with open(self.current_path, "rb") as f:
                data = f.read()
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Read failed: {e}")
            return
        all_strings = []
        if ascii_ok:
            cur = []
            for b in data:
                if 32 <= b < 127:
                    cur.append(chr(b))
                else:
                    if len(cur) >= min_len:
                        all_strings.append("".join(cur))
                    cur = []
            if len(cur) >= min_len:
                all_strings.append("".join(cur))
        if u16_ok:
            try:
                u = data.decode("utf-16-le", errors="ignore")
                cur = []
                for ch in u:
                    if 32 <= ord(ch) < 127:
                        cur.append(ch)
                    else:
                        if len(cur) >= min_len:
                            all_strings.append("".join(cur))
                        cur = []
                if len(cur) >= min_len:
                    all_strings.append("".join(cur))
            except Exception:
                pass
        self.last_extracted_strings = all_strings
        self.strings_view.setPlainText("\n".join(all_strings))
        self.statusBar().showMessage(f"Extracted {len(all_strings)} strings.")
        self.chk_suspicious_only.setChecked(False)

    def apply_strings_filter(self):
        if not self.last_extracted_strings:
            return
        if not self.chk_suspicious_only.isChecked():
            self.strings_view.setPlainText("\n".join(self.last_extracted_strings))
            self.statusBar().showMessage(f"Showing all {len(self.last_extracted_strings)} strings.")
            return

        suspicious = SuspiciousStringAnalyzer.analyze(self.last_extracted_strings)
        self.last_suspicious_strings = suspicious
        filtered = [s['string'] for s in suspicious]
        self.strings_view.setPlainText("\n".join(filtered))
        self.statusBar().showMessage(f"Showing {len(filtered)} suspicious strings out of {len(self.last_extracted_strings)}.")

    # ------------------------ Archive ------------------------
    def populate_archive_tab(self):
        self.archive_table.setRowCount(0)
        self.current_archive_entries = []
        self.archive_info_label.setText("No archive loaded.")
        if not self.current_path or not zipfile.is_zipfile(self.current_path):
            return
        try:
            zf = zipfile.ZipFile(self.current_path, "r")
            for info in zf.infolist():
                entry = {
                    "name": info.filename,
                    "size": info.file_size,
                    "compressed": info.compress_size,
                    "is_dir": info.is_dir(),
                    "path": info.filename,
                }
                self.current_archive_entries.append(entry)
            for entry in self.current_archive_entries:
                row = self.archive_table.rowCount()
                self.archive_table.insertRow(row)
                self.archive_table.setItem(row, 0, QtWidgets.QTableWidgetItem(entry["name"]))
                self.archive_table.setItem(row, 1, QtWidgets.QTableWidgetItem(str(entry["size"])))
                self.archive_table.setItem(row, 2, QtWidgets.QTableWidgetItem(str(entry["compressed"])))
                self.archive_table.setItem(row, 3, QtWidgets.QTableWidgetItem("Dir" if entry["is_dir"] else "File"))
                self.archive_table.setItem(row, 4, QtWidgets.QTableWidgetItem(entry["path"]))
            self.archive_info_label.setText(f"Archive entries: {len(self.current_archive_entries)}")
            zf.close()
        except Exception as e:
            self.archive_info_label.setText(f"Failed to open archive: {e}")

    def _get_selected_archive_entries(self):
        rows = set()
        for idx in self.archive_table.selectedIndexes():
            rows.add(idx.row())
        return [self.current_archive_entries[r] for r in rows if r < len(self.current_archive_entries)]

    def _safe_extract(self, zip_ref, member, target_dir):
        target = os.path.join(target_dir, member.filename)
        real_target = os.path.realpath(target)
        real_target_dir = os.path.realpath(target_dir)
        if not real_target.startswith(real_target_dir):
            raise ValueError(f"Path traversal detected: {member.filename}")
        return zip_ref.extract(member, target_dir)

    def archive_extract_selected(self):
        selected = self._get_selected_archive_entries()
        if not selected:
            QtWidgets.QMessageBox.information(self, "No selection", "Select entries first.")
            return
        out_dir = QtWidgets.QFileDialog.getExistingDirectory(self, "Select output directory")
        if not out_dir:
            return
        try:
            with zipfile.ZipFile(self.current_path, "r") as zf:
                for entry in selected:
                    if entry["is_dir"]:
                        continue
                    self._safe_extract(zf, zf.getinfo(entry["path"]), out_dir)
            QtWidgets.QMessageBox.information(self, "Done", f"Extracted {len(selected)} entries.")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Extraction failed: {e}")

    def archive_extract_add_evidence(self):
        selected = self._get_selected_archive_entries()
        if not selected:
            QtWidgets.QMessageBox.information(self, "No selection", "Select entries first.")
            return
        out_dir = QtWidgets.QFileDialog.getExistingDirectory(self, "Select output directory")
        if not out_dir:
            return
        added = []
        try:
            with zipfile.ZipFile(self.current_path, "r") as zf:
                for entry in selected:
                    if entry["is_dir"]:
                        continue
                    dst = self._safe_extract(zf, zf.getinfo(entry["path"]), out_dir)
                    added.append(dst)
            for p in added:
                self.add_evidence_from_path(p)
            QtWidgets.QMessageBox.information(self, "Done", f"Extracted and added {len(added)} files as evidence.")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed: {e}")

    def archive_export_csv(self):
        if not self.current_archive_entries:
            return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export Archive Listing", "archive.csv",
                                                        "CSV files (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Name", "Size", "Compressed", "Type", "Path"])
                for e in self.current_archive_entries:
                    writer.writerow(
                        [e["name"], e["size"], e["compressed"], "Dir" if e["is_dir"] else "File", e["path"]])
            self.statusBar().showMessage(f"Exported to {path}")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Export failed: {e}")

    # ------------------------ Executable & YARA ------------------------
    def populate_exe_tab(self):
        self.exe_table.setRowCount(0)
        self.exe_info.setText("")
        if not self.current_path or not PEFILE_AVAILABLE:
            if not PEFILE_AVAILABLE:
                self.exe_info.setText("pefile not installed.")
            return
        ext = os.path.splitext(self.current_path)[1].lower()
        magic = file_magic(self.current_path, 2)
        if ext not in (".exe", ".dll", ".sys") and magic != b"MZ":
            self.exe_info.setText("Not a Windows PE file.")
            return
        try:
            pe = pefile.PE(self.current_path)
            info = [f"Machine: 0x{pe.FILE_HEADER.Machine:04X}",
                    f"Sections: {pe.FILE_HEADER.NumberOfSections}",
                    f"Timestamp: {pe.FILE_HEADER.TimeDateStamp}",
                    f"Entry point: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}"]
            self.exe_info.setText("\n".join(info))
            for section in pe.sections:
                row = self.exe_table.rowCount()
                self.exe_table.insertRow(row)
                name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
                vsize = section.Misc_VirtualSize
                rsize = section.SizeOfRawData
                ent = section.get_entropy()
                self.exe_table.setItem(row, 0, QtWidgets.QTableWidgetItem(name))
                self.exe_table.setItem(row, 1, QtWidgets.QTableWidgetItem(str(vsize)))
                self.exe_table.setItem(row, 2, QtWidgets.QTableWidgetItem(str(rsize)))
                self.exe_table.setItem(row, 3, QtWidgets.QTableWidgetItem(f"{ent:.3f}"))
        except Exception as e:
            self.exe_info.setText(f"Parse error: {e}")

    def browse_yara_rules(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select YARA rules file", "",
                                                        "YARA files (*.yar *.yara);;All Files (*)")
        if path:
            self.yara_rules_path_edit.setText(path)

    def run_yara_scan(self):
        self.yara_result.clear()
        if not self.current_path:
            return
        if not YARA_AVAILABLE:
            self.yara_result.setPlainText("yara-python not installed.")
            return
        rules_path = self.yara_rules_path_edit.text().strip()
        if not rules_path:
            QtWidgets.QMessageBox.information(self, "No rules", "Select YARA rules first.")
            return
        try:
            rules = yara.compile(filepath=rules_path)
            matches = rules.match(self.current_path)
            if not matches:
                self.yara_result.setPlainText("No matches.")
            else:
                lines = []
                for m in matches:
                    lines.append(f"Rule: {m.rule}")
                    if m.meta:
                        lines.append(f"  Meta: {m.meta}")
                    if m.strings:
                        for off, sid, val in m.strings:
                            lines.append(f"  @0x{off:X} {sid}: {val!r}")
                    lines.append("")
                self.yara_result.setPlainText("\n".join(lines))
            self._log_event(self.current_path, f"YARA scan with {rules_path}")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"YARA failed: {e}")

    # ------------------------ Security ------------------------
    def encrypt_current_file(self):
        if not self.current_path:
            QtWidgets.QMessageBox.information(self, "No file", "Load a file first.")
            return
        pwd1, ok = QtWidgets.QInputDialog.getText(self, "Encrypt File", "Password:", QtWidgets.QLineEdit.Password)
        if not ok or not pwd1:
            return
        pwd2, ok = QtWidgets.QInputDialog.getText(self, "Confirm", "Confirm password:", QtWidgets.QLineEdit.Password)
        if pwd1 != pwd2:
            QtWidgets.QMessageBox.warning(self, "Mismatch", "Passwords do not match.")
            return
        dst, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save encrypted file",
                                                       self._suggest_copy_name("_enc") + ".enc",
                                                       "Encrypted files (*.enc);;All Files (*)")
        if not dst:
            return
        try:
            encrypt_file_streaming(self.current_path, dst, pwd1)
            QtWidgets.QMessageBox.information(self, "Done", f"Encrypted copy saved to {dst}")
            self._log_event(self.current_path, f"Encrypted copy created: {dst}")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Encryption failed: {e}")

    def decrypt_file_dialog(self):
        src, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select encrypted file", "",
                                                       "Encrypted files (*.enc);;All Files (*)")
        if not src:
            return
        pwd, ok = QtWidgets.QInputDialog.getText(self, "Decrypt File", "Password:", QtWidgets.QLineEdit.Password)
        if not ok or not pwd:
            return
        dst, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save decrypted file as", os.path.splitext(src)[0],
                                                       "All Files (*)")
        if not dst:
            return
        try:
            decrypt_file_streaming(src, dst, pwd)
            QtWidgets.QMessageBox.information(self, "Done", f"Decrypted file saved to {dst}")
            self._log_event(dst, f"Decrypted from {src}")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Decryption failed: {e}")

    def pdf_add_password(self):
        if not self.current_path:
            return
        if not PYPDF_AVAILABLE:
            QtWidgets.QMessageBox.information(self, "Missing lib", "pypdf not installed.")
            return
        pwd, ok = QtWidgets.QInputDialog.getText(self, "Protect PDF", "Enter password:", QtWidgets.QLineEdit.Password)
        if not ok or not pwd:
            return
        dst, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save protected PDF",
                                                       self._suggest_copy_name("_protected"), "PDF (*.pdf)")
        if not dst:
            return
        try:
            reader = PdfReader(self.current_path)
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            writer.encrypt(pwd)
            with open(dst, "wb") as f:
                writer.write(f)
            QtWidgets.QMessageBox.information(self, "Done", "PDF protected.")
            self._log_event(self.current_path, f"Password-protected copy saved to {dst}")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed: {e}")

    def secure_wipe_current(self):
        if not self.current_path:
            return
        if self.evidence_mode:
            QtWidgets.QMessageBox.warning(self, "Blocked", "Evidence Mode is ON. Wiping disabled.")
            return
        reply = QtWidgets.QMessageBox.critical(self, "Secure Wipe",
                                               f"Permanently erase:\n{self.current_path}\n\nThis cannot be undone!",
                                               QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
        if reply != QtWidgets.QMessageBox.Yes:
            return
        if secure_wipe_file(self.current_path):
            QtWidgets.QMessageBox.information(self, "Wiped", "File securely wiped and deleted.")
            self.current_path = None
            self.clear_all_tabs()
            for i in range(self.evidence_list.count()):
                item = self.evidence_list.item(i)
                if item.data(QtCore.Qt.UserRole) == self.current_path:
                    self.evidence_list.takeItem(i)
                    break
            self.populate_evidence_list()
        else:
            QtWidgets.QMessageBox.critical(self, "Error", "Secure wipe failed.")

    # ------------------------ Browser Artifacts ------------------------
    def populate_artifacts_tab(self):
        self.artifacts_table.setRowCount(0)
        self.artifacts_info_label.setText("No recognized browser artifacts.")
        self._artifacts_rows = []
        if not self.current_path or not os.path.basename(self.current_path).lower() == "history":
            return
        try:
            conn = sqlite3.connect(self.current_path)
            cur = conn.cursor()
            cur.execute(
                "SELECT last_visit_time, url, title, visit_count FROM urls ORDER BY last_visit_time DESC LIMIT 1000")
            rows = cur.fetchall()
            conn.close()
            for t, url, title, visits in rows:
                time_str = chromium_time_to_str(t)
                self._artifacts_rows.append((time_str, url or "", title or "", visits or 0))
            self._refresh_artifacts_table(self._artifacts_rows)
            self.artifacts_info_label.setText(f"Loaded {len(self._artifacts_rows)} history entries.")
        except Exception as e:
            self.artifacts_info_label.setText(f"Failed to read SQLite: {e}")

    def _refresh_artifacts_table(self, rows):
        self.artifacts_table.setRowCount(0)
        for t, url, title, visits in rows:
            r = self.artifacts_table.rowCount()
            self.artifacts_table.insertRow(r)
            self.artifacts_table.setItem(r, 0, QtWidgets.QTableWidgetItem(t))
            self.artifacts_table.setItem(r, 1, QtWidgets.QTableWidgetItem(url))
            self.artifacts_table.setItem(r, 2, QtWidgets.QTableWidgetItem(title))
            self.artifacts_table.setItem(r, 3, QtWidgets.QTableWidgetItem(str(visits)))

    def filter_artifacts(self):
        if not hasattr(self, "_artifacts_rows"):
            return
        q = self.artifacts_search_edit.text().strip().lower()
        if not q:
            self._refresh_artifacts_table(self._artifacts_rows)
            return
        filtered = [(t, url, title, visits) for (t, url, title, visits) in self._artifacts_rows
                    if q in url.lower() or q in title.lower()]
        self._refresh_artifacts_table(filtered)

    # ------------------------ Comparisons ------------------------
    def select_comparison_file(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select file to compare")
        if path:
            self.compare_target_path = path
            self.compare_path_label.setText(path)

    def run_comparison(self):
        if not self.current_path or not self.compare_target_path:
            return
        f1, f2 = self.current_path, self.compare_target_path
        res = [f"File 1: {f1}", f"File 2: {f2}"]
        try:
            s1, s2 = os.path.getsize(f1), os.path.getsize(f2)
            res.append(f"Size: {s1} vs {s2} ({'MATCH' if s1 == s2 else 'DIFF'})")
            h1 = compute_hashes(f1, ["md5"])["md5"]
            h2 = compute_hashes(f2, ["md5"])["md5"]
            res.append(f"MD5: {h1} vs {h2} ({'MATCH' if h1 == h2 else 'DIFF'})")
            if s1 < 100_000 and s2 < 100_000:
                try:
                    with open(f1, "r", errors="ignore") as fa:
                        t1 = fa.readlines()
                    with open(f2, "r", errors="ignore") as fb:
                        t2 = fb.readlines()
                    diff = difflib.unified_diff(t1, t2, fromfile="File1", tofile="File2")
                    res.append("\n--- Text Diff ---")
                    res.extend(diff)
                except Exception:
                    res.append("\n(Binary or diff failed)")
            else:
                res.append("\n(Files too large for text diff)")
        except Exception as e:
            res.append(f"Error: {e}")
        self.compare_result.setPlainText("\n".join(res))

    # ------------------------ Steganography ------------------------
    def stego_embed(self):
        if not self.current_path:
            return
        text = self.stego_input_text.toPlainText()
        if not text:
            return
        dst, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save Stego Image", self._suggest_copy_name("_stego"),
                                                       "PNG (*.png)")
        if not dst:
            return
        if SteganographyHelper.embed_text(self.current_path, dst, text):
            QtWidgets.QMessageBox.information(self, "Done", f"Text embedded into {dst}")
            self._log_event(self.current_path, f"Steganography embedded into {dst}")
        else:
            QtWidgets.QMessageBox.critical(self, "Failed", "Embedding failed.")

    def stego_extract(self):
        if not self.current_path:
            return
        text = SteganographyHelper.extract_text(self.current_path)
        if text:
            self.stego_output_text.setPlainText(text)
            QtWidgets.QMessageBox.information(self, "Found", "Secret message extracted!")
        else:
            self.stego_output_text.setPlainText("(No message found)")
            QtWidgets.QMessageBox.information(self, "Nothing", "No message detected.")

    # ------------------------ Carving ------------------------
    def run_carving(self):
        start_dir = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Directory to Carve")
        if not start_dir:
            return
        out_dir = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Output Directory for Carved Files")
        if not out_dir:
            return
        self.carve_log.appendPlainText(f"Carving sweep in {start_dir}...")
        total = 0
        for root, _, files in os.walk(start_dir):
            for name in files:
                path = os.path.join(root, name)
                if os.path.getsize(path) > 50 * 1024 * 1024:
                    self.carve_log.appendPlainText(f"Skipping large: {name}")
                    continue
                self.carve_log.appendPlainText(f"Scanning {name}...")
                results = FileCarver.carve(path, out_dir)
                if results:
                    total += len(results)
                    self.carve_log.appendPlainText(f" -> Found {len(results)} items")
        self.carve_log.appendPlainText(f"Carving complete. Total extracted: {total}")

    # ------------------------ Advanced ------------------------
    def run_malware_scan(self):
        if not self.current_path:
            return
        ent = estimate_entropy(self.current_path)
        magic_desc = detect_magic_label(file_magic(self.current_path, 8))
        res = MalwareScorer.score_file(self.current_path, ent, magic_desc, self.known_bad)
        score = res["score"]
        color = "green" if score <= 40 else ("orange" if score <= 70 else "red")
        txt = f"Malware Score: {score}/100\n\nReasons:\n" + "\n".join(f"- {r}" for r in res["reasons"])
        self.malware_result.setText(txt)
        self.malware_result.setStyleSheet(f"color: {color};")
        if "malware_score" in self.info_labels:
            self.info_labels["malware_score"].setText(str(score))
        self.update_scan_summary(None)

    def scan_macros(self):
        if not self.current_path:
            return
        found = False
        try:
            with open(self.current_path, "rb") as f:
                content = f.read(1024 * 1024)
                if b"VBA" in content or b"Macro" in content:
                    found = True
        except Exception:
            pass
        self.macro_result.setText("Suspicious keywords found" if found else "No keywords found")
        self.macro_result.setStyleSheet("color: red;" if found else "color: green;")

    def scan_embedded(self):
        if not self.current_path:
            return
        try:
            with open(self.current_path, "rb") as f:
                data = f.read(1024 * 1024)
            hits = []
            if data.count(b"%PDF") > 1:
                hits.append("Multiple PDF headers")
            if b"Microsoft Word" in data or b"Word.Document" in data:
                hits.append("OLE/Word tokens")
            if not hits:
                hits.append("No obvious embedded objects.")
            self.embedded_result.setPlainText("\n".join(hits))
        except Exception as e:
            self.embedded_result.setPlainText(f"Error: {e}")

    # ------------------------ IOC Extraction ------------------------
    def extract_and_display_iocs(self):
        if not self.current_path:
            return
        try:
            with open(self.current_path, "rb") as f:
                data = f.read(10 * 1024 * 1024)
            iocs = EnhancedIOCExtractor.extract_with_classification(data, self.file_size if hasattr(self, 'file_size') else os.path.getsize(self.current_path))
            self.last_iocs = iocs
            self.display_iocs(iocs)
        except Exception as e:
            self.iocs_text.setPlainText(f"Error extracting IOCs: {e}")

    def display_iocs(self, iocs: dict):
        lines = []
        lines.append("=== IOC EXTRACTION RESULTS ===\n")
        lines.append(f"Total IOCs: {iocs.get('total_iocs', 0)}")
        lines.append(f"External IPs: {len(iocs.get('external_ips', []))}")
        lines.append(f"Internal IPs: {len(iocs.get('internal_ips', []))}")
        lines.append(f"URLs: {len(iocs.get('urls', []))}")
        lines.append(f"Domains: {len(iocs.get('domains', []))}")
        lines.append(f"Suspicious Domains: {len(iocs.get('suspicious_domains', []))}")
        lines.append(f"Emails: {len(iocs.get('emails', []))}")
        lines.append("")
        for category in ['ips', 'urls', 'domains', 'emails']:
            items = iocs.get(category, [])
            if items:
                lines.append(f"--- {category.upper()} ---")
                for item in items[:50]:
                    lines.append(item)
                if len(items) > 50:
                    lines.append(f"... and {len(items)-50} more")
                lines.append("")
        self.iocs_text.setPlainText("\n".join(lines))
        self._log_event(self.current_path, "IOCs extracted")

    # ------------------------ Full Analysis ------------------------
    def run_full_analysis(self):
        if not self.current_path:
            QtWidgets.QMessageBox.information(self, "No file", "Load a file first.")
            return
        self.statusBar().showMessage("Starting full analysis...")
        self.worker = FullAnalysisWorker(self.current_path, self.known_bad)
        self.worker.progress.connect(self.statusBar().showMessage)
        self.worker.finished.connect(self.on_full_analysis_finished)
        self.worker.start()

    def on_full_analysis_finished(self, results):
        if not results or 'error' in results:
            self.statusBar().showMessage(f"Analysis failed: {results.get('error', 'Unknown error')}")
            return

        if 'hashes' in results:
            for algo, val in results['hashes'].items():
                if algo in self.hash_edits:
                    self.hash_edits[algo].setText(val)

        if 'entropy' in results:
            self.info_labels['entropy'].setText(f"{results['entropy']:.3f}")

        if 'malware_score' in results:
            score = results['malware_score']
            self.info_labels['malware_score'].setText(str(score))
            self.malware_result.setText(f"Malware Score: {score}/100\n\nReasons:\n" + "\n".join(f"- {r}" for r in results.get('malware_reasons', [])))

        if 'all_strings' in results:
            self.last_extracted_strings = results['all_strings']
            self.strings_view.setPlainText("\n".join(results['all_strings']))

        if 'iocs' in results:
            self.last_iocs = results['iocs']
            self.display_iocs(results['iocs'])

        if 'suspicious_strings' in results:
            self.last_suspicious_strings = results['suspicious_strings']
            if self.chk_suspicious_only.isChecked():
                filtered = [s['string'] for s in self.last_suspicious_strings]
                self.strings_view.setPlainText("\n".join(filtered))

        self.update_scan_summary(results)

        # Cache results for report generation
        self.last_mitre = results.get('mitre', {'techniques': []})
        self.last_mismatch = results.get('file_mismatch', {})
        self.last_analysis_results = results # Keep full copy

        # ------------------------ Elite Intelligence Display ------------------------
        summary = []
        analysis = results['analysis']
        
        # 1. Risk Breakdown & Confidence
        summary.append(f"Confidence Score: {analysis.get('confidence_score', 0)}/100")
        summary.append("\nRisk Breakdown:")
        for comp, val in analysis.get('risk_components', {}).items():
            summary.append(f"  - {comp.replace('_', ' ').title()}: {val}%")
        
        # 2. Malware Classification
        family = results.get('malware_family', {})
        if family.get('family') != 'UNKNOWN':
            summary.append(f"\nMalware Family: {family['family']} (Confidence: {family['confidence']})")
            summary.append(f"Reasoning: {family['reasoning']}")
        
        # 3. Anomaly Detection
        anomalies = results.get('anomalies', [])
        if anomalies and anomalies[0] != "No significant structural anomalies detected.":
            summary.append("\nStructural Anomalies Detected:")
            for a in anomalies:
                summary.append(f"  [!] {a}")

        # 4. Behavioral Profiling
        behaviors = results.get('behaviors', [])
        if behaviors:
            summary.append("\nObserved Behaviors:")
            for b in behaviors:
                summary.append(f"  • {b}")

        # 5. Impact & Recommendations
        impact = results.get('impact_assessment', {})
        if impact.get('impacts'):
            summary.append("\nPotential Impact:")
            for im in impact['impacts']:
                summary.append(f"  - {im}")
        
        if impact.get('recommendations'):
            summary.append("\nAnalyst Recommendations:")
            for rec in impact['recommendations']:
                summary.append(f"  [ACTION] {rec}")

        # Final append to the UI text area
        self.summary_findings_text.setText("\n".join(summary))

        if 'mitre' in results:
            techniques = results['mitre'].get('techniques', [])
            if techniques:
                mitre_text = "\n\nMITRE ATT&CK Techniques:\n" + "\n".join(f"- {t['id']}: {t['name']} ({t['tactic']})" for t in techniques)
                self.summary_findings_text.append(mitre_text)

        self.statusBar().showMessage("Full analysis completed.")
        QtWidgets.QMessageBox.information(self, "Analysis Complete",
            f"Analysis finished.\nRisk: {results['analysis']['classification']} ({results['analysis']['risk_score']}/100)\nConfidence: {analysis.get('confidence_score', 0)}%")

    # ------------------------ Chain of Custody & Timeline ------------------------
    def populate_chain_of_custody(self):
        self.chain_view.clear()
        if not self.current_path or self.current_path not in self.evidence_db:
            return
        events = self.evidence_db[self.current_path].get("events", [])
        lines = [f"{ts}  -  {action}" for ts, action in events]
        self.chain_view.setPlainText("\n".join(lines))

    def update_timeline(self):
        if not self.current_case_id or self.current_case_id not in self.cases:
            self.timeline_view.setPlainText("")
            return
        records = []
        for path in self.cases[self.current_case_id]["evidences"]:
            if path in self.evidence_db:
                for ts, action in self.evidence_db[path].get("events", []):
                    records.append((ts, path, action))
        records.sort(key=lambda x: x[0])
        lines = [f"{ts}  [{os.path.basename(p)}]  {action}" for ts, p, action in records]
        self.timeline_view.setPlainText("\n".join(lines))

    def update_dashboard(self):
        pass

    # ------------------------ Misc ------------------------
    def directory_scan(self):
        directory = QtWidgets.QFileDialog.getExistingDirectory(self, "Select directory to scan")
        if not directory:
            return
        out, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save scan results", "directory_scan.csv",
                                                       "CSV files (*.csv)")
        if not out:
            return
        try:
            with open(out, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Path", "Size", "Modified", "SHA256"])
                for root, _, files in os.walk(directory):
                    for name in files:
                        path = os.path.join(root, name)
                        try:
                            size = os.path.getsize(path)
                            mtime = datetime.datetime.fromtimestamp(os.path.getmtime(path)).strftime(
                                "%Y-%m-%d %H:%M:%S")
                            h = compute_hashes(path, ["sha256"])["sha256"]
                            writer.writerow([path, size, mtime, h])
                        except Exception:
                            continue
            QtWidgets.QMessageBox.information(self, "Done", f"Scan saved to {out}")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"CSV write failed: {e}")

    def import_hashes(self, known_good: bool):
        label = "known-good" if known_good else "known-bad"
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, f"Import {label} hashes (CSV)", "", "CSV files (*.csv)")
        if not path:
            return
        count = 0
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.reader(f)
                for row in reader:
                    if not row:
                        continue
                    h = row[0].strip().lower()
                    if not h or h.startswith("sha"):
                        continue
                    if known_good:
                        if h not in self.known_good:
                            self.known_good.add(h)
                            count += 1
                    else:
                        if h not in self.known_bad:
                            self.known_bad.add(h)
                            count += 1
            QtWidgets.QMessageBox.information(self, "Imported", f"Imported {count} {label} hashes.")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Import failed: {e}")

    def export_report(self):
        if not self.current_path:
            QtWidgets.QMessageBox.information(self, "No evidence", "Load a file first.")
            return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export HTML report", "report.html",
                                                        "HTML files (*.html)")
        if not path:
            return
        ev = self._ensure_evidence_entry(self.current_path)
        
        # We need a proper results dict for ReportGenerator
        # In a real app we'd cache the FullAnalysisWorker results
        # Here we'll try to reconstruct from what we have in evidence_db/UI
        results = {
            'file_path': self.current_path,
            'file_size': os.path.getsize(self.current_path),
            'mime_type': self.info_labels['mime'].text(),
            'entropy': float(self.info_labels['entropy'].text()) if self.info_labels['entropy'].text() != "-" else 0.0,
            'hashes': {k: self.hash_edits[k].text() for k in self.hash_edits},
            'analysis': {
                'classification': self.summary_risk_label.text().split(":")[1].split("(")[0].strip() if ":" in self.summary_risk_label.text() else "UNKNOWN",
                'risk_score': self.summary_risk_label.text().split("(")[1].split("/")[0].strip() if "(" in self.summary_risk_label.text() else 0,
                'explanation': self.summary_explanation_label.text()
            },
            'iocs': getattr(self, 'last_iocs', {}),
            'suspicious_strings': getattr(self, 'last_suspicious_strings', []),
            'mitre': getattr(self, 'last_mitre', {'techniques': []}),
            'file_mismatch': getattr(self, 'last_mismatch', {})
        }

        if ReportGenerator.generate_report(results, path):
             self.statusBar().showMessage(f"Forensic report saved to {path}")
             QtWidgets.QMessageBox.information(self, "Report Generated", f"Report successfully saved to:\n{path}")
        else:
             QtWidgets.QMessageBox.critical(self, "Error", "Failed to generate report.")

    def analyze_case(self):
        if not self.current_case_id:
            return
        ev_paths = list(self.cases[self.current_case_id]["evidences"])
        if not ev_paths:
            QtWidgets.QMessageBox.information(self, "Analyze", "No evidence in this case.")
            return
        sha_map = {}
        case_results = []
        for path in ev_paths:
            if os.path.isfile(path):
                # In a real-world scenario, we'd use fully analyzed results from a database.
                # For this implementation, we'll do a quick pass to gather basic data for correlation.
                try:
                    res = {
                        'file_path': path,
                        'hashes': compute_hashes(path, ['sha256']),
                        'iocs': EnhancedIOCExtractor.extract_with_classification(open(path, "rb").read(1024*1024), os.path.getsize(path)),
                        'analysis': {'risk_score': 0} # Simplified
                    }
                    case_results.append(res)
                except Exception:
                    continue
        
        correlation = CaseAnalyzer.analyze(case_results)
        
        msg = f"CASE CORRELATION SUMMARY\n"
        msg += f"------------------------\n"
        msg += f"Case Risk Level: {correlation['case_risk']}\n"
        msg += f"Average Risk Score: {correlation['avg_score']}\n"
        msg += f"Findings: {correlation['correlation_summary']}\n\n"
        
        if correlation['shared_hashes']:
            msg += "Shared Hashes Found:\n"
            for h, files in correlation['shared_hashes'].items():
                msg += f"- {h[:16]}...: {', '.join(files)}\n"
        
        if correlation['high_risk_files']:
            msg += "\nHigh Risk Files identified:\n"
            for f in correlation['high_risk_files']:
                 msg += f"- {f['name']} (Score: {f['score']})\n"

        QtWidgets.QMessageBox.information(self, "Case-Level Correlation Analysis", msg)

    def show_command_palette(self):
        dlg = CommandPaletteDialog(self, self.commands)
        dlg.exec()

    def set_time_mode(self, mode):
        self.time_mode = mode
        if self.current_path:
            self.populate_overview()
        self.statusBar().showMessage(f"Time mode: {mode}")

    def clear_all_tabs(self):
        for key in self.info_labels:
            self.info_labels[key].setText("")
        for algo in self.hash_edits:
            self.hash_edits[algo].setText("")
        self.entropy_bar.setValue(0)
        self.metadata_table.setRowCount(0)
        self.hex_view.clear()
        self.strings_view.clear()
        self.archive_table.setRowCount(0)
        self.exe_table.setRowCount(0)
        self.exe_info.clear()
        self.yara_result.clear()
        self.artifacts_table.setRowCount(0)
        self.preview_label.setText("No preview available.")
        self.preview_info.clear()
        self.chain_view.clear()
        self.iocs_text.clear()
        self.summary_risk_label.setText("Risk Level: N/A")
        self.summary_filetype_label.setText("File Type: -")
        self.summary_mismatch_label.setText("")
        self.summary_entropy_label.setText("Entropy: -")
        self.summary_malware_label.setText("Malware Score: -")
        self.summary_ioc_count_label.setText("IOCs: 0")
        self.summary_findings_text.setPlainText("")
        self.summary_explanation_label.setText("")
        self.last_extracted_strings = []
        self.last_iocs = {}

    # ------------------------ Help ------------------------
    def show_quick_start(self):
        QtWidgets.QMessageBox.information(self, "Quick Start",
                                          "1. Create/select a case from the top bar.\n"
                                          "2. Add evidence via 'Open File' or drag & drop.\n"
                                          "3. Double-click evidence to load it.\n"
                                          "4. Use tabs for detailed analysis.\n"
                                          "5. Evidence Mode (ON) prevents in-place modifications.\n"
                                          "6. Click 'Run Full Analysis' for comprehensive scan.")

    def show_tab_overview(self):
        QtWidgets.QMessageBox.information(self, "Tab Overview",
                                          "Home: Dashboard\nEvidence Overview: File info & hashes\nMetadata: EXIF/PDF/audio tags\nHex & Strings: Hex dump and string extraction\nArchive: ZIP contents\nExecutable: PE analysis & YARA\nSecurity: Encryption, wipe, PDF password\nBrowser Artifacts: Chromium history\nPreview: Image/text preview\nComparisons: Diff two files\nSteganography: LSB hiding\nFile Carving: Header scanning\nAdvanced: Malware score, macros\nChain of Custody: Event log\nCase Timeline: Chronological events\nIOC Extraction: URLs, IPs, domains, emails")

    def show_keyboard_shortcuts(self):
        QtWidgets.QMessageBox.information(self, "Shortcuts",
                                          "Ctrl+O: Open file\nCtrl+Shift+R: Export report\nF5: Reverify hashes\nCtrl+E: Encrypt file\nCtrl+D: Decrypt file\nCtrl+Shift+S: Extract strings\nCtrl+Shift+A: Analyze case\nCtrl+Shift+P: Command palette")

    def show_about(self):
        QtWidgets.QMessageBox.information(self, "About ForensiX Studio",
                                          f"{APP_TITLE}\nVersion 3.1\nIndustry‑grade forensic decision engine.\n\nUses AES-256-GCM, PBKDF2 with 600k iterations, secure wipe (shred/overwrite).")

    # ------------------------ Drag & Drop & State ------------------------
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if path and os.path.isfile(path):
                self.add_evidence_from_path(path)

    def save_state(self):
        try:
            data = {
                "case_counter": self.case_counter,
                "evidence_counter": self.evidence_counter,
                "current_case_id": self.current_case_id,
                "cases": {cid: {"name": c["name"], "notes": c.get("notes", ""), "evidences": list(c["evidences"])}
                          for cid, c in self.cases.items()},
                "evidence_db": {},
                "known_good": list(self.known_good),
                "known_bad": list(self.known_bad),
                "window_geometry": base64.b64encode(self.saveGeometry()).decode("ascii"),
                "window_state": base64.b64encode(self.saveState()).decode("ascii"),
            }
            for path, ev in self.evidence_db.items():
                data["evidence_db"][path] = {
                    "case_id": ev.get("case_id"),
                    "evidence_id": ev.get("evidence_id"),
                    "baseline_hashes": ev.get("baseline_hashes"),
                    "events": list(ev.get("events", [])),
                    "tags": list(ev.get("tags", [])),
                    "note": ev.get("note", ""),
                }
            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Save state failed: {e}")

    def load_state(self):
        if not os.path.exists(STATE_FILE):
            return
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.case_counter = data.get("case_counter", 1)
            self.evidence_counter = data.get("evidence_counter", 1)
            self.current_case_id = data.get("current_case_id")
            self.cases = {}
            for cid, c in data.get("cases", {}).items():
                self.cases[cid] = {"name": c.get("name", cid), "notes": c.get("notes", ""),
                                   "evidences": set(c.get("evidences", []))}
            self.evidence_db = {}
            for path, ev in data.get("evidence_db", {}).items():
                self.evidence_db[path] = {
                    "case_id": ev.get("case_id"),
                    "evidence_id": ev.get("evidence_id"),
                    "baseline_hashes": ev.get("baseline_hashes"),
                    "events": [tuple(e) for e in ev.get("events", [])],
                    "tags": set(ev.get("tags", [])),
                    "note": ev.get("note", ""),
                }
            self.known_good = set(data.get("known_good", []))
            self.known_bad = set(data.get("known_bad", []))
            geom = data.get("window_geometry")
            if geom:
                self.restoreGeometry(base64.b64decode(geom))
            state = data.get("window_state")
            if state:
                self.restoreState(base64.b64decode(state))
        except Exception as e:
            logger.error(f"Load state failed: {e}")

    def closeEvent(self, event):
        self.save_state()
        super().closeEvent(event)


# ------------------------ Main ------------------------
def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName(APP_TITLE)
    window = FileInsightWindow()
    window.showMaximized()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()