#!/usr/bin/env python3
# xorxor.py
# Usage: python xorxor.py

from itertools import cycle
import binascii
import string

# input hex values (dari soal)
k1_hex    = "3c3f0193af37d2ebbc50cc6b91d27cf61197"
k21_hex   = "ff76edcad455b6881b92f726987cbf30c68c"
k23_hex   = "611568312c102d4d921f26199d39fe973118"
k1234_hex = "91ec5a6fa8a12f908f161850c591459c3887"
f45_hex   = "0269dd12fe3435ea63f63aef17f8362cdba8"

def hx(s): return bytes.fromhex(s)

k1    = hx(k1_hex)
k21   = hx(k21_hex)
k23   = hx(k23_hex)
k1234 = hx(k1234_hex)
f45   = hx(f45_hex)

# XOR helpers
def bxor(a,b):
    return bytes(x ^ y for x,y in zip(a,b))

# pad/truncate helper: ensure lengths match by repeating the shorter
def repeat_to_len(key, length):
    return bytes((list(key)[i % len(key)] for i in range(length)))

# reconstruct keys (KEY1 known = k1)
KEY1 = k1
KEY2 = bxor(k21, KEY1)                 # KEY2 = k21 ^ KEY1
KEY3 = bxor(k23, KEY2)                 # KEY3 = k23 ^ KEY2
# KEY4 = k1234 ^ KEY1 ^ KEY3 ^ KEY2
tmp = bxor(KEY1, KEY3)
tmp = bxor(tmp, KEY2)
KEY4 = bxor(k1234, tmp)

print("[*] Derived key lengths:")
print(" KEY1 len", len(KEY1))
print(" KEY2 len", len(KEY2))
print(" KEY3 len", len(KEY3))
print(" KEY4 len", len(KEY4))
print(" f45 len ", len(f45))

# fx = f45 ^ KEY4 = FLAG ^ KEY5
# align lengths
L = max(len(f45), len(KEY4))
fx = bxor(repeat_to_len(f45, L), repeat_to_len(KEY4, L))

print("[*] fx length:", len(fx))

# We assume KEY5 is 4 bytes repeating, and FLAG likely contains "cry{"
crib = b"cry{"

candidates = []

for offset in range(4):
    # determine KEY5 first 4 bytes by aligning crib at offset
    # fx[offset:offset+len(crib)] = FLAG[offset:offset+len(crib)] ^ KEY5_repeating
    # so KEY5_bytes_at_positions = fx_segment ^ crib
    # But because KEY5 repeats every 4 bytes, we can recover each of the 4 bytes independently
    key5 = [None]*4
    ok = True
    for i, ch in enumerate(crib):
        pos = offset + i
        if pos >= len(fx):
            ok = False
            break
        kbyte = fx[pos] ^ ch
        idx = pos % 4
        if key5[idx] is None:
            key5[idx] = kbyte
        else:
            if key5[idx] != kbyte:
                ok = False
                break
    if not ok:
        continue
    # fill None with 0x00 (we can try all 256 on missing, but keep simple)
    for i in range(4):
        if key5[i] is None:
            key5[i] = 0
    key5_bytes = bytes(key5)
    # build repeating KEY5 aligned with offset (we must rotate key so that offset aligns)
    # create repeating keystream same length of fx
    keystream = bytes((key5_bytes[(i - offset) % 4] for i in range(len(fx))))
    flag_candidate = bxor(fx, keystream)
    # heuristics: printable and contains cry{
    try:
        flag_str = flag_candidate.decode('utf-8', errors='strict')
    except:
        flag_str = None
    printable = flag_candidate and all((32 <= b < 127) or b in (9,10,13) for b in flag_candidate)
    if flag_str and ("cry{" in flag_str or "cry{" in flag_str):
        candidates.append((offset, key5_bytes.hex(), flag_str))
    else:
        # keep also some printable candidates for manual inspection
        if printable:
            candidates.append((offset, key5_bytes.hex(), flag_candidate.decode('utf-8', errors='replace')))

print("\n[*] Candidates (offset, key5 hex, flag):")
for c in candidates:
    print(c)

if not candidates:
    print("\n[-] Tidak menemukan kandidat otomatis. Menampilkan 10 dekripsi awal (offset 0..3) untuk inspeksi:")
    for offset in range(4):
        key5 = b"\x00\x00\x00\x00"  # fallback
        keystream = bytes((key5[(i - offset) % 4] for i in range(len(fx))))
        flag_candidate = bxor(fx, keystream)
        print(f"offset {offset} : {flag_candidate[:200]!r}")
