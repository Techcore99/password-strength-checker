#!/usr/bin/env python3
"""Password Strength Checker - BSc Cybersecurity project.

Estimates password strength using entropy, pattern detection, a common-password
list, and (optionally) the Have I Been Pwned breach database via k-anonymity.
"""
import argparse
import getpass
import hashlib
import math
import re
import string
import sys
import urllib.request

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "qwerty", "abc123", "letmein",
    "monkey", "dragon", "111111", "iloveyou", "admin", "welcome", "login",
    "master", "sunshine", "princess", "football", "baseball", "shadow",
    "superman", "trustno1", "passw0rd", "starwars", "whatever", "freedom",
    "hello", "charlie", "donald", "batman", "access", "michael", "jordan",
    "qwertyuiop", "asdfghjkl", "zaq12wsx", "1q2w3e4r", "changeme", "secret",
}

SEQUENCES = [
    "abcdefghijklmnopqrstuvwxyz", "0123456789",
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
]

LEET = {"@": "a", "4": "a", "3": "e", "0": "o", "1": "i", "!": "i",
        "$": "s", "5": "s", "7": "t"}

GUESSES_PER_SECOND = 1e10  # offline attack on a fast hash (GPU cluster)

LABELS = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]


def charset_size(pw):
    """Size of the character pool the password draws from."""
    pool = 0
    if any(c in string.ascii_lowercase for c in pw): pool += 26
    if any(c in string.ascii_uppercase for c in pw): pool += 26
    if any(c in string.digits for c in pw): pool += 10
    if any(c in string.punctuation for c in pw): pool += 32
    if any(c not in string.printable for c in pw): pool += 100
    return pool


def entropy_bits(pw):
    """Naive entropy: length * log2(pool size)."""
    pool = charset_size(pw)
    return len(pw) * math.log2(pool) if pool else 0.0


def has_sequence(pw, run=3):
    low = pw.lower()
    for seq in SEQUENCES:
        for s in (seq, seq[::-1]):
            for i in range(len(s) - run + 1):
                if s[i:i + run] in low:
                    return True
    return False


def has_repeats(pw):
    return re.search(r"(.)\1{2,}", pw) is not None


def has_year(pw):
    return re.search(r"(19|20)\d{2}", pw) is not None


def is_common(pw):
    low = pw.lower()
    normalised = "".join(LEET.get(c, c) for c in low)
    stripped = re.sub(r"[^a-z]", "", normalised)
    return low in COMMON_PASSWORDS or normalised in COMMON_PASSWORDS or (
        len(stripped) >= 4 and stripped in COMMON_PASSWORDS)


def contains_common(pw):
    """Common password (>=6 chars) hidden inside a longer one, e.g. 'P@ssw0rd123'."""
    norm = "".join(LEET.get(c, c) for c in pw.lower())
    return any(w in norm for w in COMMON_PASSWORDS if len(w) >= 6)


def hibp_count(pw):
    """Times the password appears in known breaches (HIBP k-anonymity API).

    Only the first 5 hex chars of the SHA-1 hash leave your machine.
    Returns None if the lookup fails (e.g. offline).
    """
    sha1 = hashlib.sha1(pw.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        req = urllib.request.Request(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": "password-strength-checker-student-project"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            for line in resp.read().decode().splitlines():
                h, _, count = line.partition(":")
                if h == suffix:
                    return int(count)
        return 0
    except Exception:
        return None


def format_time(seconds):
    if seconds < 1: return "instantly"
    units = [("year", 31536000), ("day", 86400), ("hour", 3600),
             ("minute", 60), ("second", 1)]
    if seconds > 31536000 * 1e9: return "billions of years+"
    for name, size in units:
        if seconds >= size:
            n = int(seconds // size)
            return f"{n:,} {name}{'s' if n != 1 else ''}"
    return "instantly"


def analyze(pw):
    """Return a dict describing the password's strength."""
    feedback = []
    raw = entropy_bits(pw)
    eff = raw

    if len(pw) < 12:
        feedback.append("Use at least 12 characters (14+ is better).")
    if not re.search(r"[a-z]", pw): feedback.append("Add lowercase letters.")
    if not re.search(r"[A-Z]", pw): feedback.append("Add uppercase letters.")
    if not re.search(r"\d", pw): feedback.append("Add digits.")
    if not re.search(r"[^\w\s]", pw): feedback.append("Add symbols.")

    if is_common(pw):
        eff = min(eff, 10)
        feedback.append("This is (or closely resembles) a very common password.")
    elif contains_common(pw):
        eff -= 30
        feedback.append("Contains a common password - adding digits/symbols to it doesn't help.")
    if has_sequence(pw):
        eff -= 10
        feedback.append("Avoid sequences like 'abc', '123' or 'qwerty'.")
    if has_repeats(pw):
        eff -= 8
        feedback.append("Avoid repeated characters like 'aaa'.")
    if has_year(pw):
        eff -= 6
        feedback.append("Avoid years - they are easy to guess.")
    eff = max(eff, 0)

    if eff < 28: score = 0
    elif eff < 36: score = 1
    elif eff < 60: score = 2
    elif eff < 80: score = 3
    else: score = 4

    if score >= 3 and not feedback:
        feedback.append("Looks good! Consider using a password manager.")

    seconds = (2 ** eff) / GUESSES_PER_SECOND / 2  # average = half the space
    return {
        "length": len(pw),
        "raw_entropy": round(raw, 1),
        "effective_entropy": round(eff, 1),
        "score": score,
        "label": LABELS[score],
        "crack_time": format_time(seconds),
        "feedback": feedback,
    }


def report(pw, check_breach=False):
    r = analyze(pw)
    bar = "#" * (r["score"] + 1) + "-" * (4 - r["score"])
    print(f"\n  Strength : [{bar}] {r['label']}")
    print(f"  Length   : {r['length']}")
    print(f"  Entropy  : {r['raw_entropy']} bits "
          f"(adjusted for patterns: {r['effective_entropy']} bits)")
    print(f"  Crack est: {r['crack_time']} (offline, 10B guesses/sec)")
    if check_breach:
        n = hibp_count(pw)
        if n is None:
            print("  Breaches : lookup failed (offline?)")
        elif n:
            print(f"  Breaches : FOUND {n:,} times in known data breaches!")
        else:
            print("  Breaches : not found in known breaches")
    if r["feedback"]:
        print("  Tips:")
        for tip in r["feedback"]:
            print(f"   - {tip}")
    print()
    return r


def main():
    parser = argparse.ArgumentParser(description="Password Strength Checker")
    parser.add_argument("--breach", action="store_true",
                        help="check Have I Been Pwned (needs internet)")
    args = parser.parse_args()
    try:
        pw = getpass.getpass("Enter password (hidden): ")
    except (EOFError, KeyboardInterrupt):
        sys.exit(1)
    if not pw:
        sys.exit("No password entered.")
    report(pw, args.breach)


if __name__ == "__main__":
    main()
