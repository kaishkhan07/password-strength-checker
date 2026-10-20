"""
All-in-one Password Strength Checker (single file, no external libraries)

Features:
 1. Basic checks   : length, uppercase, lowercase, digit, special character
 2. Pattern checks : common passwords, sequences, repeats, keyboard walks,
                     leetspeak, dictionary words, personal info, year/date
 3. Scoring        : entropy, penalties, score 0-4, crack time estimate
 4. Advanced       : breach check (Have I Been Pwned, k-anonymity),
                     actionable feedback, passphrase support,
                     secure password generator
 5. Security       : the password is never logged or stored, and is read
                     with hidden input (getpass)
"""

import getpass
import hashlib
import math
import re
import secrets
import string
import urllib.request

# ----------------------------------------------------------------------
# Data
# ----------------------------------------------------------------------
COMMON_PASSWORDS = {
    "password", "password1", "password123", "123456", "12345678", "123456789",
    "qwerty", "qwerty123", "abc123", "admin", "admin123", "admin@123",
    "letmein", "welcome", "welcome1", "iloveyou", "monkey", "dragon",
    "football", "baseball", "sunshine", "princess", "master", "login",
    "passw0rd", "p@ssw0rd", "india123", "test123", "root", "toor",
}

DICTIONARY_WORDS = {
    "password", "admin", "welcome", "sunshine", "football", "cricket",
    "dragon", "monkey", "master", "login", "secret", "india", "hello",
    "princess", "shadow", "superman", "batman", "freedom", "whatever",
}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]

LEET_MAP = str.maketrans({"@": "a", "4": "a", "0": "o", "1": "i", "!": "i",
                          "3": "e", "$": "s", "5": "s", "7": "t", "+": "t"})

SPECIALS = set(string.punctuation)


# ----------------------------------------------------------------------
# 1. Basic checks
# ----------------------------------------------------------------------
def check_length(pw):
    return {"length": len(pw), "ok": len(pw) >= 12, "min_ok": len(pw) >= 8}


def check_charset(pw):
    return {
        "upper": any(c.isupper() for c in pw),
        "lower": any(c.islower() for c in pw),
        "digit": any(c.isdigit() for c in pw),
        "special": any(c in SPECIALS for c in pw),
    }


def charset_size(cs):
    size = 0
    if cs["lower"]:
        size += 26
    if cs["upper"]:
        size += 26
    if cs["digit"]:
        size += 10
    if cs["special"]:
        size += len(SPECIALS)
    return size


# ----------------------------------------------------------------------
# 2. Weak pattern detection
# ----------------------------------------------------------------------
def deleet(pw):
    return pw.lower().translate(LEET_MAP)


def check_common_passwords(pw):
    low = pw.lower()
    return low in COMMON_PASSWORDS or deleet(pw) in COMMON_PASSWORDS


def has_sequence(pw, run=4):
    """Detects ascending/descending runs such as abcd, 1234, dcba."""
    low = pw.lower()
    count = 1
    for i in range(1, len(low)):
        diff = ord(low[i]) - ord(low[i - 1])
        if diff in (1, -1) and (low[i].isalnum() and low[i - 1].isalnum()):
            if i > 1 and (ord(low[i - 1]) - ord(low[i - 2])) == diff:
                count += 1
            else:
                count = 2
            if count >= run:
                return True
        else:
            count = 1
    return False


def has_repeats(pw, run=3):
    return re.search(r"(.)\1{%d,}" % (run - 1), pw) is not None


def has_keyboard_walk(pw, run=4):
    low = pw.lower()
    for row in KEYBOARD_ROWS:
        for r in (row, row[::-1]):
            for i in range(len(r) - run + 1):
                if r[i:i + run] in low:
                    return True
    return False


def has_dictionary_word(pw):
    cleaned = deleet(pw)
    return [w for w in DICTIONARY_WORDS if w in cleaned]


def has_personal_info(pw, personal):
    low = pw.lower()
    hits = []
    for item in personal:
        item = item.strip().lower()
        if len(item) >= 3 and item in low:
            hits.append(item)
    return hits


def has_year_or_date(pw):
    return re.search(r"(19|20)\d{2}", pw) is not None or \
        re.search(r"\b\d{6,8}\b", pw) is not None


def check_patterns(pw, personal):
    return {
        "common": check_common_passwords(pw),
        "sequence": has_sequence(pw),
        "repeats": has_repeats(pw),
        "keyboard": has_keyboard_walk(pw),
        "leet_only": deleet(pw) != pw.lower() and
                     deleet(pw).isalpha() and len(pw) < 14,
        "words": has_dictionary_word(pw),
        "personal": has_personal_info(pw, personal),
        "year_date": has_year_or_date(pw),
    }


# ----------------------------------------------------------------------
# 4a. Breach check (k-anonymity: only the first 5 hash characters are sent)
# ----------------------------------------------------------------------
def check_breach(pw, timeout=5):
    """Returns the breach count, 0 if not found, or None if the check failed."""
    sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        req = urllib.request.Request(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": "password-strength-checker"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
        for line in body.splitlines():
            h, _, count = line.partition(":")
            if h.strip() == suffix:
                return int(count)
        return 0
    except Exception:
        return None


# ----------------------------------------------------------------------
# 3. Entropy, crack time, score
# ----------------------------------------------------------------------
def calculate_entropy(pw, cs):
    size = charset_size(cs)
    if size == 0 or not pw:
        return 0.0
    return len(pw) * math.log2(size)


def estimate_crack_time(entropy, guesses_per_sec=1e10):
    """Offline attack with fast hardware (10 billion guesses per second)."""
    seconds = (2 ** entropy) / 2 / guesses_per_sec
    units = [("seconds", 60), ("minutes", 60), ("hours", 24), ("days", 365),
             ("years", 100), ("centuries", float("inf"))]
    if seconds < 1:
        return "instantly"
    value = seconds
    for name, step in units:
        if value < step:
            return f"{value:.0f} {name}"
        value /= step
    return "centuries+"


def is_passphrase(pw):
    words = re.split(r"[\s\-_.]+", pw)
    words = [w for w in words if w.isalpha()]
    return len(words) >= 4 and len(pw) >= 20


def calculate_score(results):
    """Returns (score from 0 to 4, entropy after penalties)."""
    ent = results["entropy"]
    pat = results["patterns"]

    # Penalties
    if pat["common"]:
        return 0, 0.0
    if results["breach"]:  # a breach count above 0 means the password is unsafe
        return 0, min(ent, 20.0)
    if pat["sequence"]:
        ent -= 12
    if pat["repeats"]:
        ent -= 10
    if pat["keyboard"]:
        ent -= 12
    if pat["words"]:
        ent -= 15
    if pat["personal"]:
        ent -= 20
    if pat["year_date"]:
        ent -= 6
    if pat["leet_only"]:
        ent -= 10
    ent = max(ent, 0.0)

    # Passphrases: length matters more than character variety
    if is_passphrase(results["password"]) and not pat["common"]:
        ent = max(ent, len(results["password"]) * 2.5)

    if ent < 28:
        score = 0
    elif ent < 36:
        score = 1
    elif ent < 60:
        score = 2
    elif ent < 80:
        score = 3
    else:
        score = 4

    # Serious weak patterns cap the score regardless of raw entropy
    if pat["personal"] or pat["keyboard"] or pat["sequence"] or pat["repeats"]:
        score = min(score, 1)
    elif pat["words"] or pat["leet_only"]:
        score = min(score, 2)
    return score, ent


LABELS = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]


# ----------------------------------------------------------------------
# 4b. Feedback
# ----------------------------------------------------------------------
def generate_feedback(results):
    tips = []
    L, cs, pat = results["length"], results["charset"], results["patterns"]
    pw = results["password"]

    if not is_passphrase(pw):
        if not L["min_ok"]:
            tips.append("The password is too short. Use at least 8 characters, ideally 12 or more.")
        elif not L["ok"]:
            tips.append("Increase the length to 12 or more characters. Length has the biggest impact.")
        if not cs["upper"]:
            tips.append("Add an uppercase letter (A-Z).")
        if not cs["lower"]:
            tips.append("Add a lowercase letter (a-z).")
        if not cs["digit"]:
            tips.append("Add a digit (0-9).")
        if not cs["special"]:
            tips.append("Add a special character (for example !@#$%).")
    if pat["common"]:
        tips.append("This is a commonly used password. Do not use it.")
    if pat["sequence"]:
        tips.append("Remove sequences such as abcd or 1234.")
    if pat["repeats"]:
        tips.append("Remove repeated characters such as aaa or 111.")
    if pat["keyboard"]:
        tips.append("Remove keyboard patterns such as qwerty or asdf.")
    if pat["words"]:
        tips.append(f"A dictionary word was found: {', '.join(pat['words'])}. "
                    "Use random words or a passphrase instead.")
    if pat["personal"]:
        tips.append(f"Personal information was found: {', '.join(pat['personal'])}. "
                    "Do not use your name, date of birth, or phone number.")
    if pat["year_date"]:
        tips.append("Avoid year or date patterns such as 2026 or 15081999.")
    if pat["leet_only"]:
        tips.append("Leetspeak substitutions (for example p@ssw0rd) add little strength. "
                    "Attackers try them first.")
    if results["breach"]:
        tips.append(f"This password has appeared in data breaches {results['breach']:,} times. "
                    "Change it immediately.")
    if not tips:
        tips.append("Excellent password. Use a different one for every site and store it in a password manager.")
    return tips


# ----------------------------------------------------------------------
# 4c. Secure generators (use `secrets`, not `random`)
# ----------------------------------------------------------------------
def generate_password(length=16):
    length = max(length, 12)
    pools = [string.ascii_lowercase, string.ascii_uppercase,
             string.digits, string.punctuation]
    chars = [secrets.choice(p) for p in pools]
    allchars = "".join(pools)
    chars += [secrets.choice(allchars) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def generate_passphrase(words=5):
    wordlist = sorted(DICTIONARY_WORDS | {
        "river", "cloud", "orange", "tiger", "planet", "silver", "forest",
        "rocket", "window", "garden", "pencil", "yellow", "thunder", "island",
        "bridge", "candle", "falcon", "marble", "violet", "anchor"})
    return "-".join(secrets.choice(wordlist) for _ in range(words)) + \
        f"-{secrets.randbelow(90) + 10}"


# ----------------------------------------------------------------------
# Main analyzer
# ----------------------------------------------------------------------
def analyze(pw, personal=(), do_breach=True):
    cs = check_charset(pw)
    results = {
        "password": pw,
        "length": check_length(pw),
        "charset": cs,
        "patterns": check_patterns(pw, personal),
        "entropy": calculate_entropy(pw, cs),
        "breach": check_breach(pw) if do_breach else None,
    }
    score, adj = calculate_score(results)
    results["score"] = score
    results["adj_entropy"] = adj
    results["crack_time"] = estimate_crack_time(adj)
    results["feedback"] = generate_feedback(results)
    return results


def show(results):
    bar = "#" * (results["score"] + 1) + "-" * (4 - results["score"])
    print("\n" + "=" * 52)
    print(f" Strength   : [{bar}] {LABELS[results['score']]} ({results['score']}/4)")
    print(f" Length     : {results['length']['length']}")
    print(f" Entropy    : {results['entropy']:.1f} bits "
          f"(after penalties: {results['adj_entropy']:.1f})")
    print(f" Crack time : ~{results['crack_time']} (offline attack, fast hardware)")
    b = results["breach"]
    if b is None:
        print(" Breach     : check skipped or unavailable (offline)")
    elif b == 0:
        print(" Breach     : not found in known data breaches")
    else:
        print(f" Breach     : FOUND {b:,} times in data breaches!")
    print("-" * 52)
    print(" Suggestions:")
    for t in results["feedback"]:
        print(f"  - {t}")
    print("=" * 52 + "\n")


def main():
    print("Password Strength Checker")
    print("(Your password is never saved or logged.)\n")
    while True:
        print("1) Check password   2) Generate password   "
              "3) Generate passphrase   4) Exit")
        choice = input("Choice: ").strip()
        if choice == "1":
            pw = getpass.getpass("Enter password (input is hidden): ")
            if not pw:
                print("The password cannot be empty.\n")
                continue
            info = input("Personal info such as name, DOB, phone "
                         "(comma-separated, optional): ")
            personal = [x for x in info.split(",") if x.strip()]
            use_net = input("Run breach check? (uses Have I Been Pwned, "
                            "needs internet) [y/N]: ")
            show(analyze(pw, personal, use_net.lower().startswith("y")))
        elif choice == "2":
            print("\nGenerated password:", generate_password(16), "\n")
        elif choice == "3":
            print("\nGenerated passphrase:", generate_passphrase(), "\n")
        elif choice == "4":
            print("Goodbye.")
            break
        else:
            print("Invalid choice. Please enter 1, 2, 3, or 4.\n")


if __name__ == "__main__":
    main()