#!/usr/bin/env python3
"""
Complete C2 Traffic Analyzer for Grurat malware
Extracts ALL commands, keys, encrypted payloads, and decrypts everything
"""

import struct
import base64
import zlib
import re
import string
import sys
from pathlib import Path
from collections import defaultdict

try:
    from scapy.all import rdpcap, TCP, Raw, IP
except ImportError:
    print("[-] Error: scapy not installed")
    print("[*] Install with: pip install scapy")
    sys.exit(1)

# Protocol message types
MSG_TEXT = 1
MSG_COMMAND = 32
MSG_PING = 254
MSG_PONG = 255

C2_HOST = '34.124.239.18'
C2_PORT = 9000

# Mahjong tile alphabet for decoding
MJ_ALPHABET = ['🀇', '🀈', '🀉', '🀊', '🀋', '🀌', '🀍', '🀎', '🀏', 
               '🀐', '🀑', '🀒', '🀓', '🀔', '🀕', '🀖']
PNG_SIG = b'\x89PNG\r\n\x1a\n'
CHUNK_TYPE = b'stEg'

def mahjong_decode(mj_str):
    """Decode mahjong tile encoding to bytes"""
    if len(mj_str) % 2 != 0:
        raise ValueError("Invalid mahjong string length")
    
    MJ_DEC = {ch: i for i, ch in enumerate(MJ_ALPHABET)}
    out = bytearray()
    
    for i in range(0, len(mj_str), 2):
        hi, lo = mj_str[i], mj_str[i + 1]
        if hi not in MJ_DEC or lo not in MJ_DEC:
            raise ValueError(f"Invalid mahjong character")
        out.append(MJ_DEC[hi] << 4 | MJ_DEC[lo])
    
    return bytes(out)

def xor_decrypt(ciphertext: bytes, key: str) -> str:
    """XOR decrypt with key"""
    key_bytes = key.encode('utf-8')
    decrypted_bytes = bytearray()
    
    for i in range(len(ciphertext)):
        decrypted_bytes.append(ciphertext[i] ^ key_bytes[i % len(key_bytes)])
    
    return decrypted_bytes.decode('utf-8', errors='ignore')

def extract_steg_chunk(png_data):
    """Extract mahjong-encoded payload from PNG stEg chunk"""
    try:
        if not png_data.startswith(PNG_SIG):
            return None
        
        i = len(PNG_SIG)
        while i + 12 <= len(png_data):
            length = struct.unpack('>I', png_data[i:i+4])[0]
            chunk_type = png_data[i+4:i+8]
            
            if chunk_type == CHUNK_TYPE:
                payload_data = png_data[i+8:i+8+length]
                return payload_data.decode('utf-8', errors='ignore')
            
            i += 12 + length
        
        return None
    except Exception as e:
        return None

def extract_strings_from_shellcode(shellcode_bytes):
    """Extract printable ASCII strings from shellcode"""
    printable_set = set(string.printable.encode())
    current_string = []
    strings_found = []
    
    for byte in shellcode_bytes:
        if byte in printable_set and byte not in [0, 1]:
            current_string.append(chr(byte))
        else:
            if len(current_string) >= 4:
                strings_found.append(''.join(current_string))
            current_string = []
    
    if current_string and len(current_string) >= 4:
        strings_found.append(''.join(current_string))
    
    return strings_found

def find_key_in_shellcode(shellcode_bytes):
    """Extract the key from shellcode"""
    strings = extract_strings_from_shellcode(shellcode_bytes)
    
    # Look for key pattern with "> PH" suffix (from shellcode)
    for s in strings:
        # Pattern: xxxFF> PH or xxxRF> PH
        if '> PH' in s and (s.startswith('RF') or s.startswith('FF') or 'RF>' in s or 'FF>' in s):
            # Extract the key part before "> PH"
            key_part = s.split('> PH')[0].split('PH')[-1]
            if (key_part.endswith('FF') or key_part.endswith('RF')) and len(key_part) >= 4:
                return key_part
    
    # Look for key pattern (ends with FF or RF) without suffix
    for s in strings:
        if (s.endswith('FF') or s.endswith('RF')) and len(s) >= 4:
            clean_part = s[:-2]
            if clean_part.replace('_', '').replace('-', '').isalnum():
                return s
    
    # Look near "key:" string
    for i, s in enumerate(strings):
        if 'key:' in s.lower() or s.strip() == 'key':
            # Check strings before and after
            for j in range(max(0, i - 2), min(i + 5, len(strings))):
                if j == i:
                    continue
                candidate = strings[j]
                # Check for key with "> PH" pattern
                if '> PH' in candidate and ('FF>' in candidate or 'RF>' in candidate):
                    key_part = candidate.split('> PH')[0].split('PH')[-1]
                    if key_part.endswith('FF') or key_part.endswith('RF'):
                        return key_part
    
    return None

def decrypt_exfiltrated_data(mahjong_payload, key):
    """Decrypt the full exfiltration chain: Mahjong -> Base64 -> XOR -> Plaintext"""
    try:
        decoded_bytes = mahjong_decode(mahjong_payload)
        encrypted_data = base64.b64decode(decoded_bytes)
        plaintext = xor_decrypt(encrypted_data, key)
        return plaintext
    except Exception as e:
        return None

def parse_message(data):
    """Parse a single message from the C2 protocol"""
    if len(data) < 1:
        return None
    
    msg_type = data[0]
    
    if msg_type == MSG_TEXT:
        if len(data) < 5:
            return None
        text_len = struct.unpack('!I', data[1:5])[0]
        if len(data) < 5 + text_len:
            return None
        text = data[5:5+text_len].decode('utf-8', errors='ignore')
        return {'type': 'TEXT', 'content': text}
    
    elif msg_type == MSG_COMMAND:
        if len(data) < 3:
            return None
        cmd_len = struct.unpack('!H', data[1:3])[0]
        if len(data) < 3 + cmd_len:
            return None
        cmd = data[3:3+cmd_len].decode('utf-8', errors='ignore')
        return {'type': 'COMMAND', 'content': cmd}
    
    elif msg_type == MSG_PING:
        return {'type': 'PING', 'content': ''}
    
    elif msg_type == MSG_PONG:
        if len(data) < 3:
            return None
        flag_len = struct.unpack('!H', data[1:3])[0]
        if len(data) < 3 + flag_len:
            return None
        flag = data[3:3+flag_len].decode('utf-8', errors='ignore')
        return {'type': 'PONG', 'content': flag}
    
    return None

def reassemble_tcp_streams(packets):
    """Reassemble TCP streams"""
    streams = defaultdict(lambda: bytearray())
    
    for pkt in packets:
        if TCP in pkt and Raw in pkt and IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            
            stream_id = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))
            streams[stream_id].extend(bytes(pkt[Raw].load))
    
    return streams

def extract_pngs_from_stream(stream_data):
    """Extract all PNG files from a TCP stream"""
    pngs = []
    pos = 0
    
    while True:
        png_start = stream_data.find(PNG_SIG, pos)
        if png_start == -1:
            break
        
        iend_pos = stream_data.find(b'IEND', png_start)
        if iend_pos == -1:
            pos = png_start + 1
            continue
        
        png_end = iend_pos + 8
        png_data = stream_data[png_start:png_end]
        
        if CHUNK_TYPE in png_data:
            pngs.append(png_data)
        
        pos = png_end
    
    return pngs

def analyze_pcap(pcap_file):
    """Main analysis function"""
    print("=" * 80)
    print("COMPLETE C2 TRAFFIC ANALYZER")
    print("=" * 80)
    print()
    
    print(f"[*] Loading PCAP: {pcap_file}\n")
    packets = rdpcap(str(pcap_file))
    
    commands = []
    responses = []
    downloaded_pngs = []
    uploaded_pngs = []
    all_keys = set()
    
    # Phase 1: Extract C2 commands/responses
    print("[PHASE 1] Extracting C2 Commands & Responses")
    print("-" * 80)
    
    for pkt in packets:
        if TCP in pkt and Raw in pkt:
            if pkt[TCP].sport == C2_PORT or pkt[TCP].dport == C2_PORT:
                payload = bytes(pkt[Raw].load)
                msg = parse_message(payload)
                
                if msg:
                    direction = "C2→Client" if pkt[TCP].sport == C2_PORT else "Client→C2"
                    
                    if msg['type'] == 'COMMAND':
                        commands.append(msg['content'])
                        print(f"  [{direction}] COMMAND: {msg['content']}")
                    elif msg['type'] == 'TEXT':
                        responses.append(msg['content'])
                        print(f"  [{direction}] RESPONSE: {msg['content']}")
    
    # Phase 2: Extract PNGs from HTTP streams
    print(f"\n[PHASE 2] Extracting PNG Files from HTTP Streams")
    print("-" * 80)
    
    streams = reassemble_tcp_streams(packets)
    
    for stream_id, stream_data in streams.items():
        stream_bytes = bytes(stream_data)
        
        if b'HTTP/' in stream_bytes or b'GET ' in stream_bytes or b'POST ' in stream_bytes:
            pngs = extract_pngs_from_stream(stream_bytes)
            
            for png in pngs:
                if b'GET ' in stream_bytes[:200]:
                    downloaded_pngs.append(png)
                    print(f"  [+] Downloaded PNG: {len(png)} bytes")
                elif b'POST ' in stream_bytes[:200] and b'update.php' in stream_bytes[:1000]:
                    uploaded_pngs.append(png)
                    print(f"  [+] Uploaded PNG: {len(png)} bytes")
    
    # Phase 3: Extract keys from downloaded PNGs (shellcode)
    print(f"\n[PHASE 3] Extracting Keys from Shellcode")
    print("-" * 80)
    
    for idx, png in enumerate(downloaded_pngs):
        print(f"\n  [Downloaded PNG #{idx+1}]")
        
        mahjong_data = extract_steg_chunk(png)
        if not mahjong_data:
            print(f"    [-] No stEg chunk found")
            continue
        
        try:
            decoded = mahjong_decode(mahjong_data)
            
            if decoded.startswith(b'Z'):
                decoded = zlib.decompress(decoded[1:])
                print(f"    [+] Decompressed shellcode: {len(decoded)} bytes")
            
            # Extract strings and find key
            strings = extract_strings_from_shellcode(decoded)
            key = find_key_in_shellcode(decoded)
            
            if key:
                all_keys.add(key)
                print(f"    [!] KEY FOUND: {key}")
            else:
                print(f"    [+] Shellcode strings: {strings[:10]}")
                print(f"    [-] No key pattern found")
        
        except Exception as e:
            print(f"    [-] Error: {e}")
    
    # Add manual known key
    all_keys.add('niarRF')
    
    # Phase 4: Decrypt uploaded PNGs
    print(f"\n[PHASE 4] Decrypting Uploaded PNGs")
    print("-" * 80)
    print(f"\n  Keys to try: {sorted(all_keys)}\n")
    
    decrypted_data = []
    
    for idx, png in enumerate(uploaded_pngs):
        print(f"  [Uploaded PNG #{idx+1}]")
        
        mahjong_payload = extract_steg_chunk(png)
        if not mahjong_payload:
            print(f"    [-] No stEg chunk")
            continue
        
        print(f"    [+] Mahjong payload: {len(mahjong_payload)} chars")
        print(f"    [+] Sample: {mahjong_payload[:40]}...")
        
        for key in sorted(all_keys):
            plaintext = decrypt_exfiltrated_data(mahjong_payload, key)
            
            if plaintext and 'flag{' in plaintext:
                print(f"    [✓] SUCCESS with key: {key}")
                print(f"    [✓] Decrypted: {plaintext}")
                decrypted_data.append({
                    'png_index': idx + 1,
                    'key': key,
                    'plaintext': plaintext
                })
                break
            elif plaintext and len(plaintext) > 5:
                # Show partial results even without flag{}
                print(f"    [?] Key '{key}' produced: {plaintext[:80]}")
        
        print()
    
    # Final Summary
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"\nCommands received:       {len(commands)}")
    print(f"Responses sent:          {len(responses)}")
    print(f"Downloaded PNGs:         {len(downloaded_pngs)}")
    print(f"Uploaded PNGs:           {len(uploaded_pngs)}")
    print(f"Keys extracted:          {len(all_keys)}")
    print(f"Successfully decrypted:  {len(decrypted_data)}")
    
    if all_keys:
        print(f"\n[KEYS FOUND]")
        for key in sorted(all_keys):
            print(f"  • {key}")
    
    if decrypted_data:
        print(f"\n[DECRYPTED FLAGS]")
        print("-" * 80)
        for item in decrypted_data:
            print(f"\n  PNG #{item['png_index']} | Key: {item['key']}")
            print(f"  └─ {item['plaintext']}")
            
            # Extract CTF flag format
            if item['plaintext'].startswith('flag{') and '}' in item['plaintext']:
                flag_content = item['plaintext'].split('flag{')[1].split('}')[0]
                print(f"  └─ CTF Format: forensic{{{flag_content}}}")
    
    print("\n" + "=" * 80)

def main():
    if len(sys.argv) < 2:
        print("Usage: python c2_parser.py <pcap_file>")
        print("Example: python c2_parser.py grurat.pcap")
        sys.exit(1)
    
    pcap_file = Path(sys.argv[1])
    
    if not pcap_file.exists():
        print(f"[-] Error: File not found: {pcap_file}")
        sys.exit(1)
    
    try:
        analyze_pcap(pcap_file)
        print("[*] Analysis complete!\n")
    except Exception as e:
        print(f"\n[-] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
