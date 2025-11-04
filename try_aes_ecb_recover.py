#!/usr/bin/env python3
"""
try_aes_ecb_recover.py

Try to recover files encrypted with AES-128-ECB when key is derived from an ID string
(e.g., ransom ID "EEBF306F-3483").

Usage:
  python3 try_aes_ecb_recover.py --id "EEBF306F-3483" --input /path/to/encrypted.file --outdir ./recovered
  python3 try_aes_ecb_recover.py --id "EEBF306F-3483" --input-dir /path/to/encrypted_files --outdir ./recovered --recursive

Options:
  --id           Ransom ID string used to derive key (required)
  --input        Single encrypted file to test (mutually exclusive with --input-dir)
  --input-dir    Directory of encrypted files to test (non-recursive unless --recursive)
  --outdir       Directory to write recovered candidates (default: ./recovered)
  --recursive    Recurse input-dir
  --max-bytes    Number of header bytes to read for magic detection (default: 8192)
  --force-write  Write decrypted outputs even if no known magic detected (not recommended)
  --verbose      Verbose output
"""

import argparse
import os
import hashlib
from Crypto.Cipher import AES

MAGICS = {
    b'PK\x03\x04': 'zip',
    b'%PDF-': 'pdf',
    b'MZ': 'pe',
    b'\x89PNG\r\n\x1a\n': 'png',
    b'\xff\xd8\xff': 'jpg',
    b'GIF87a': 'gif',
    b'GIF89a': 'gif',
    b'\x7fELF': 'elf',
    b'BM': 'bmp'
}

def to16(b: bytes) -> bytes:
    """Normalize/trim/pad to 16 bytes."""
    if len(b) < 16:
        return b.ljust(16, b'\x00')
    return b[:16]

def derive_candidates(id_str: str):
    """Return list of (name, 16-byte-key) candidate keys."""
    s = id_str
    s_nodash = s.replace('-', '')
    candidates = []

    # Raw variants
    candidates.append(("raw", to16(s.encode('utf-8'))))
    candidates.append(("raw_nodash", to16(s_nodash.encode('utf-8'))))
    candidates.append(("raw_upper", to16(s.upper().encode('utf-8'))))
    candidates.append(("raw_lower", to16(s.lower().encode('utf-8'))))

    # Hash-based
    candidates.append(("md5", hashlib.md5(s.encode('utf-8')).digest()))
    candidates.append(("md5_nodash", hashlib.md5(s_nodash.encode('utf-8')).digest()))
    candidates.append(("sha256_trunc", hashlib.sha256(s.encode('utf-8')).digest()[:16]))
    candidates.append(("sha1_trunc", hashlib.sha1(s.encode('utf-8')).digest()[:16]))

    # Some double/triple variants common in malware
    candidates.append(("md5_md5", hashlib.md5(hashlib.md5(s.encode('utf-8')).digest()).digest()))
    candidates.append(("md5_upper", hashlib.md5(s.upper().encode('utf-8')).digest()))
    candidates.append(("md5_lower", hashlib.md5(s.lower().encode('utf-8')).digest()))

    # Remove duplicates, keep order
    uniq = []
    seen = set()
    for name, key in candidates:
        if key not in seen:
            uniq.append((name, key))
            seen.add(key)
    return uniq

def pkcs7_unpad(data: bytes):
    """Attempt PKCS#7 unpad. Returns unpadded bytes or None if invalid."""
    if not data:
        return None
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        return None
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        return None
    return data[:-pad_len]

def decrypt_ecb_full(ciphertext: bytes, key: bytes):
    """Decrypt ciphertext with AES-128-ECB. Only decrypt full 16-byte blocks."""
    if len(ciphertext) < 16:
        return None
    # decrypt full blocks; leave tail as-is if any
    nfull = (len(ciphertext) // 16) * 16
    cipher = AES.new(key, AES.MODE_ECB)
    plain = cipher.decrypt(ciphertext[:nfull])
    if nfull < len(ciphertext):
        plain += ciphertext[nfull:]
    return plain

def detect_magic(plain: bytes):
    """Return (desc, magic) if any known magic header found."""
    for magic, desc in MAGICS.items():
        if plain.startswith(magic):
            return desc, magic
    return None, None

def process_file(path: str, id_str: str, outdir: str, max_bytes=8192, force_write=False, verbose=False):
    try:
        with open(path, 'rb') as f:
            header = f.read(max_bytes)
            f.seek(0)
            full = f.read()
    except Exception as e:
        print(f"[!] Failed reading {path}: {e}")
        return []

    candidates = derive_candidates(id_str)
    results = []

    for name, key in candidates:
        plain_head = decrypt_ecb_full(header, key)
        if plain_head is None:
            continue
        desc, magic = detect_magic(plain_head)
        likely = bool(desc)
        # Also attempt unpad and check ascii/text heuristics
        plain_full = decrypt_ecb_full(full, key)
        unpadded = None
        if plain_full is not None:
            unpadded = pkcs7_unpad(plain_full)
        # decide to write:
        wrote = False
        if likely:
            outfn = os.path.join(outdir, f"{os.path.basename(path)}.decrypted.{name}")
            try:
                with open(outfn, 'wb') as out:
                    out.write(plain_full if plain_full is not None else b'')
                wrote = True
                print(f"[+] {path} -> candidate '{name}' looks like {desc}; wrote {outfn}")
            except Exception as e:
                print(f"[!] Failed writing {outfn}: {e}")
        elif force_write:
            outfn = os.path.join(outdir, f"{os.path.basename(path)}.decrypted.{name}")
            try:
                with open(outfn, 'wb') as out:
                    out.write(plain_full if plain_full is not None else b'')
                wrote = True
                print(f"[+] {path} -> candidate '{name}' (force-write) wrote {outfn}")
            except Exception as e:
                print(f"[!] Failed writing {outfn}: {e}")

        # verbose logging
        if verbose:
            is_text = False
            try:
                sample = (plain_head or b'')[:256]
                # heuristics: printable ratio
                printable = sum(1 for c in sample if 32 <= c < 127)
                is_text = (len(sample) > 0 and (printable / len(sample)) > 0.8)
            except Exception:
                is_text = False
            results.append({
                'file': path,
                'candidate': name,
                'key_hex': key.hex(),
                'magic_detected': desc,
                'likely_plain_text': is_text,
                'wrote': wrote
            })
        else:
            results.append({
                'file': path,
                'candidate': name,
                'key_hex': key.hex(),
                'magic_detected': desc,
                'wrote': wrote
            })
    return results

def iter_files(input_path: str, recursive: bool):
    if os.path.isfile(input_path):
        yield input_path
    else:
        if recursive:
            for root, _, files in os.walk(input_path):
                for f in files:
                    yield os.path.join(root, f)
        else:
            for f in os.listdir(input_path):
                p = os.path.join(input_path, f)
                if os.path.isfile(p):
                    yield p

def main():
    parser = argparse.ArgumentParser(description="Try AES-128-ECB recovery using ID-derived keys")
    parser.add_argument("--id", required=True, help="Ransom ID (e.g. EEBF306F-3483)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--input", help="Single encrypted file to test")
    group.add_argument("--input-dir", help="Directory of encrypted files to test")
    parser.add_argument("--outdir", default="./recovered", help="Output directory")
    parser.add_argument("--recursive", action="store_true", help="Recurse input-dir")
    parser.add_argument("--max-bytes", type=int, default=8192, help="Bytes of header to read for magic detection")
    parser.add_argument("--force-write", action="store_true", help="Write outputs even if no magic detected (not recommended)")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    targets = []
    if args.input:
        targets = [args.input]
    else:
        targets = list(iter_files(args.input_dir, args.recursive))

    total = 0
    for t in targets:
        total += 1
        print(f"[*] Processing ({total}/{len(targets)}) {t}")
        res = process_file(t, args.id, args.outdir, max_bytes=args.max_bytes, force_write=args.force_write, verbose=args.verbose)
        for r in res:
            if r.get('magic_detected'):
                print(f"    -> candidate {r['candidate']} detected magic {r['magic_detected']} key={r['key_hex']}")
            elif args.verbose:
                print(f"    -> candidate {r['candidate']} no magic (key={r['key_hex']}) wrote={r['wrote']}")
    print("[*] Done.")

if __name__ == "__main__":
    main()
