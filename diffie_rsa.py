import argparse
import json
import sys
import time
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import math

# try import gmpy2 for speed
try:
    import gmpy2
    from gmpy2 import iroot as gmpy2_iroot
    HAS_GMPY2 = True
except Exception:
    gmpy2 = None
    HAS_GMPY2 = False

def generate_instance(secret_bytes: bytes, verbose=True):
    # generate primes / params similarly to challenge
    p = getPrime(1024)
    q = getPrime(1024)
    p_dh = getPrime(2048)
    g = getPrime(512)
    a = getPrime(512)
    b = getPrime(512)

    def generate_public_int(gv, av, pmod):
        return (gv ^ av) % pmod  # as in vulnerable code: g ^ a % p

    def generate_shared_secret(Av, bv, pmod):
        return (Av ^ bv) % pmod

    n = p * q
    e = 3
    flag = secret_bytes
    flag_int = bytes_to_long(flag)
    A = generate_public_int(g, a, p_dh)
    B = generate_public_int(g, b, p_dh)
    shared_int = generate_shared_secret(A, b, p_dh)
    flag2 = flag_int ^ shared_int
    c = pow(flag2, e, n)

    instance = {
        "e": e,
        "n": int(n),
        "c": int(c),
        "p_dh": int(p_dh),
        "g": int(g),
        "A": int(A),
        "B": int(B),
        # include shared_int for debugging (attacker normally doesn't have it)
        "shared_int_debug": int(shared_int),
        "secret_plain_debug": secret_bytes.decode(errors="replace")
    }
    if verbose:
        print("e =", instance["e"])
        print("n =", instance["n"])
        print("c =", instance["c"])
        print("p_dh =", instance["p_dh"])
        print("g =", instance["g"])
        print("A =", instance["A"])
        print("B =", instance["B"])
        print("# debug: shared_int (not normally disclosed) =", instance["shared_int_debug"])
    return instance

def save_instance_json(instance: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(instance, f, indent=2)
    print("[*] saved instance to", path)

def integer_cuberoot_with_gmp(n_val):
    # returns (root, exact_bool)
    root, exact = gmpy2_iroot(n_val, 3)
    return int(root), bool(exact)

def integer_cuberoot_fallback(n_val):
    # binary search fallback
    lo = 0
    hi = 1 << ((n_val.bit_length() + 2) // 3 + 2)
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if mid**3 <= n_val:
            lo = mid
        else:
            hi = mid
    return lo, (lo**3 == n_val)

def find_flag2_by_search(c, n, max_k=200000, report=5000):
    """
    Try k = 0..max_k: check t = c + k*n is a perfect cube.
    If found, return (k, flag2).
    """
    start = time.time()
    iroot_func = (integer_cuberoot_with_gmp if HAS_GMPY2 else integer_cuberoot_fallback)
    for k in range(0, max_k+1):
        if (k % report) == 0:
            elapsed = time.time() - start
            print(f"[search] k={k} elapsed={elapsed:.1f}s")
        t = c + k * n
        root, exact = iroot_func(t)
        if exact:
            print(f"[+] found exact cube for k={k}")
            return k, int(root)
    return None, None

def recover_flag_from_values(e, n, c, p_dh, g, A, B, max_k=200000, shared_int_given=None):
    # compute shared_int as attacker would given g,A,B
    # the vulnerable code used: A = (g ^ a) % p_dh; B = (g ^ b) % p_dh
    # and shared_int = (A ^ b) % p_dh. Attacker can compute b_mod = g ^ B, then shared_int = A ^ b_mod
    # Equivalent to earlier reasoning: b_mod = g ^ B; shared_int = A ^ b_mod
    b_mod = g ^ B
    shared_int = A ^ b_mod
    print("[*] computed shared_int (int)")

    # try direct cube root of c first (fast)
    if HAS_GMPY2:
        root, exact = integer_cuberoot_with_gmp(c)
    else:
        root, exact = integer_cuberoot_fallback(c)
    if exact:
        flag2 = int(root)
        print("[*] exact cube root of c found (k=0).")
    else:
        print("[!] direct cube root not exact; searching for k so that c + k*n is perfect cube")
        k_found, flag2 = find_flag2_by_search(c, n, max_k=max_k)
        if k_found is None:
            print("[-] no exact cube found up to max_k =", max_k)
            return None
        print("[*] found flag2 with k =", k_found)

    # recover flag_int and convert to bytes
    flag_int = flag2 ^ shared_int
    # convert to bytes
    if flag_int == 0:
        flag_bytes = b"\x00"
    else:
        flag_len = (flag_int.bit_length() + 7) // 8
        flag_bytes = long_to_bytes(flag_int)
    return {
        "flag_bytes": flag_bytes,
        "flag_text": flag_bytes.decode("utf-8", errors="replace"),
        "flag_int": flag_int,
        "flag2": flag2,
        "shared_int": shared_int
    }

def parse_args():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate")
    g.add_argument("--secret", required=True, help="secret flag text, e.g. 'cry{...}'")
    g.add_argument("--json-out", default="instance.json", help="save printed instance to JSON")

    r = sub.add_parser("recover")
    r.add_argument("--json", help="path to JSON instance (as produced by generate)")
    # allow direct values
    r.add_argument("--e", type=int)
    r.add_argument("--n", type=int)
    r.add_argument("--c", type=int)
    r.add_argument("--p_dh", type=int)
    r.add_argument("--g", type=int)
    r.add_argument("--A", type=int)
    r.add_argument("--B", type=int)
    r.add_argument("--max-k", type=int, default=200000, help="max k to search (default 200000)")
    return p.parse_args()

def main():
    args = parse_args()

    if args.cmd == "generate":
        inst = generate_instance(args.secret.encode("utf-8"), verbose=True)
        save_instance_json(inst, args.json_out)
        print("[*] run: python diffie_rsa_tool.py recover --json", args.json_out)

    elif args.cmd == "recover":
        if args.json:
            with open(args.json, "r", encoding="utf-8") as fh:
                inst = json.load(fh)
            e = int(inst["e"]); n = int(inst["n"]); c = int(inst["c"])
            p_dh = int(inst["p_dh"]); g = int(inst["g"]); A = int(inst["A"]); B = int(inst["B"])
        else:
            # require all direct fields
            if None in (args.e, args.n, args.c, args.p_dh, args.g, args.A, args.B):
                print("When not using --json you must supply --e --n --c --p_dh --g --A --B")
                sys.exit(1)
            e, n, c, p_dh, g, A, B = args.e, args.n, args.c, args.p_dh, args.g, args.A, args.B

        print("[*] HAS_GMPY2 =", HAS_GMPY2)
        res = recover_flag_from_values(e, n, c, p_dh, g, A, B, max_k=args.max_k)
        if res is None:
            print("[-] recovery failed.")
            sys.exit(2)
        print("\n=== RECOVERY RESULT ===")
        print("shared_int (attacker computed) :", res["shared_int"])
        print("flag2 (int)                    :", res["flag2"])
        print("flag_int (int)                 :", res["flag_int"])
        print("flag bytes (hex)               :", res["flag_bytes"].hex())
        print("flag text (utf-8, replace)     :", res["flag_text"])
        # optionally save flag
        with open("recovered_flag.bin", "wb") as fh:
            fh.write(res["flag_bytes"])
        print("[*] saved recovered_flag.bin")

if __name__ == "__main__":
    main()
