#!/usr/bin/env python3

## This simple script will deobfuscate the python script that utilized obfuscation method with Reverse -> Base64 -> Zlib (like python payload from https://freecodingtools.org/tools/obfuscator/python) and reveal the final python without executing it

import base64, zlib, re, argparse, sys

def decode_layer(data: bytes) -> bytes:
    """Try to decode one obfuscation layer: reverse -> b64 -> zlib"""
    try:
        decoded = base64.b64decode(data[::-1])
        return zlib.decompress(decoded)
    except Exception:
        return None

def extract_blob(data: bytes) -> bytes | None:
    """Extract the b'....' blob inside exec((_)(b'...'))"""
    m = re.search(
        br"exec\(\(_\)\(b['\"](?P<blob>[A-Za-z0-9+/=_\r\n\-]+)['\"]\)\)",
        data,
    )
    return m.group("blob") if m else None

def deobfuscate(input_path: str) -> tuple[bytes, int]:
    """Fully deobfuscate, return final payload and number of layers"""
    with open(input_path, "rb") as f:
        data = f.read()

    layer = 0
    while True:
        blob = extract_blob(data)
        if not blob:
            break
        decoded = decode_layer(blob)
        if not decoded:
            break
        data = decoded
        layer += 1

    return data, layer

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Python obfuscation deobfuscator")
    ap.add_argument("-i", "--input", required=True, help="Input obfuscated .py file")
    ap.add_argument("-o", "--output", default="final_payload.py",
                    help="Output file (ignored if --stdout is used)")
    ap.add_argument("--stdout", action="store_true",
                    help="Print final payload to stdout instead of writing to file")
    args = ap.parse_args()

    final, layers = deobfuscate(args.input)

    if args.stdout:
        sys.stdout.buffer.write(final)
    else:
        with open(args.output, "wb") as f:
            f.write(final)
        print(f"[+] Finished after {layers} layers. Final payload saved at: {args.output}")
