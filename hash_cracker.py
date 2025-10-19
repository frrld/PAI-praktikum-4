import sys
import os
import hashlib
import argparse
from time import time

# Target hashes (ubah jika perlu)
TARGET_KECCAK_OR_SHA3_256 = "28cc09d8d8959871a97b24a07d87bcb05b9f3e7ac6d9f20ff82196ca5f908b2c".lower()
TARGET_MD5 = "6c569aabbf7775ef8fc570e228c16b98".lower()

# --- Import Keccak (pycryptodome) jika tersedia ---
have_keccak = False
_keccak_mod = None
try:
    # pycryptodome menyediakan Crypto.Hash.keccak
    from Crypto.Hash import keccak as _keccak_mod  # type: ignore
    have_keccak = True
except Exception:
    have_keccak = False

def keccak256_hex(data: bytes) -> str:
    if have_keccak and _keccak_mod is not None:
        h = _keccak_mod.new(digest_bits=256)
        h.update(data)
        return h.hexdigest()
    else:
        h = hashlib.sha3_256()
        h.update(data)
        return h.hexdigest()

def md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def check_candidate(raw: bytes, targets, case_insensitive=False):
    found = {}
    # cek original
    k = keccak256_hex(raw)
    if k == targets[0]:
        found['keccak'] = raw.decode(errors='replace')
    m = md5_hex(raw)
    if m == targets[1]:
        found['md5'] = raw.decode(errors='replace')

    # opsi: coba lower/upper jika diaktifkan dan belum ditemukan
    if case_insensitive and not found:
        try:
            s = raw.decode('utf-8', errors='ignore')
        except:
            s = None
        if s is not None:
            for cand in (s.lower().encode(), s.upper().encode()):
                if keccak256_hex(cand) == targets[0]:
                    found['keccak'] = cand.decode(errors='replace')
                if md5_hex(cand) == targets[1]:
                    found['md5'] = cand.decode(errors='replace')
                if found:
                    break
    return found

def main():
    parser = argparse.ArgumentParser(description="Hash cracker for Keccak/SHA3-256 and MD5")
    parser.add_argument("wordlist", help="path to wordlist (one candidate per line)")
    parser.add_argument("--show-every", type=int, default=100000, help="print progress every N lines (default: 100000)")
    parser.add_argument("--case-insensitive", action="store_true", help="also try lowercase/uppercase variants")
    parser.add_argument("--out-file", default="cracked_results.txt", help="file to save cracked results")
    args = parser.parse_args()

    if not os.path.isfile(args.wordlist):
        print("Wordlist not found:", args.wordlist)
        sys.exit(1)

    print("Targets:")
    print("  Keccak/SHA3-256:", TARGET_KECCAK_OR_SHA3_256)
    print("  MD5            :", TARGET_MD5)
    print()

    if have_keccak:
        print("[info] pycryptodome detected -> using Crypto.Hash.keccak (Keccak-256).")
    else:
        print("[info] pycryptodome NOT found -> using hashlib.sha3_256 (SHA3-256) as fallback.")
        print("[note] Jika target memang Keccak-256, install pycryptodome: pip install pycryptodome")
    print()

    targets = (TARGET_KECCAK_OR_SHA3_256, TARGET_MD5)
    found_any = {}
    total = 0
    start = time()

    out_f = open(args.out_file, "a", encoding="utf-8")

    try:
        with open(args.wordlist, "rb") as fh:
            for line in fh:
                total += 1
                if total % args.show_every == 0:
                    elapsed = time() - start
                    print(f"[progress] lines={total} elapsed={elapsed:.1f}s  found={len(found_any)}")
                candidate = line.rstrip(b"\r\n")
                if not candidate:
                    continue
                res = check_candidate(candidate, targets, case_insensitive=args.case_insensitive)
                if res:
                    for ktype, val in res.items():
                        if ktype not in found_any:
                            found_any[ktype] = val
                            msg = f"[FOUND] {ktype} -> {val}"
                            print(msg)
                            out_f.write(msg + "\n")
                    if 'keccak' in found_any and 'md5' in found_any:
                        break
    finally:
        out_f.close()

    elapsed = time() - start
    print("\nDone. Lines checked:", total)
    print("Elapsed: {:.1f}s".format(elapsed))
    if found_any:
        print("Results:")
        for k, v in found_any.items():
            print(f"  {k} : {v}")
        print(f"\nSaved cracked results to {args.out_file}")
    else:
        print("No matches found in this wordlist. Try a larger wordlist (e.g. rockyou), or install pycryptodome and retry.")

if __name__ == "__main__":
    main()
