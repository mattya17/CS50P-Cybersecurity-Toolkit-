import csv, random, re, string
from collections import defaultdict
from datetime import datetime

COMMON_PW = ["123456", "password", "12345678", "qwerty", "abc123", "111111", "123123", "admin", "welcome"]
ALPHA = string.ascii_lowercase

def ask_int(prompt, default=None):
    while True:
        raw = input(prompt).strip()
        if raw == "" and default is not None:
            return default
        try:
            return int(raw)
        except ValueError:
            print("please enter a valid number")

def main():
    running = True
    while running:
        print("\n=== Cybersecurity Toolkit ===")
        print("1) Password Toolkit")
        print("2) Cipher Toolkit")
        print("3) Log Analyzer")
        print("4) Exit")
        choice = input("Choice: ").strip()

        if choice == "1":
            run_password_toolkit()
        elif choice == "2":
            run_cipher_toolkit()
        elif choice == "3":
            run_log_analyzer()
        elif choice == "4":
            running = False
        else:
            print("invalid option")
    print("Exiting the program.")

def run_password_toolkit():
    print("\n1) check password")
    print("2) generate password")
    c = input("> ").strip()
    if c == "1":
        pw = input("password to check: ")
        score, notes = check_password_strength(pw)
        print("score:", score, "/5")
        for n in notes:
            print("-", n)
    elif c == "2":
        length = ask_int("length (default 12): ", default=12)
        print("generated password ->", generate_secure_password(length))
    else:
        print("invalid option")

def check_password_strength(pw):
    score = 0
    notes = []
    if len(pw) >= 8:
        score += 1
    else:
        notes.append("at least 8 characters")
    if len(pw) >= 12:
        score += 1
    if re.search(r"[A-Z]", pw):
        score += 1
    else:
        notes.append("missing an uppercase letter")
    if re.search(r"\d", pw):
        score += 1
    else:
        notes.append("missing a digit")
    if re.search(r"[^A-Za-z0-9]", pw):
        score += 1
    else:
        notes.append("missing a symbol")
    if has_common_pattern(pw):
        score -= 2
        notes.append("pattern too common/predictable")
    if score < 0:
        score = 0
    if len(notes) == 0:
        notes.append("great password!")
    return score, notes

def has_common_pattern(pw):
    pw_low = pw.lower()
    if pw_low in COMMON_PW:
        return True
    seqs = ["0123456789", "abcdefghijklmnopqrstuvwxyz"]
    for s in seqs:
        i = 0
        while i < len(s) - 2:
            if s[i:i+3] in pw_low:
                return True
            i += 1
    return False

def generate_secure_password(length=12):
    if length < 8:
        length = 8
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    symbols = "!?$%&*#@"
    chars = [random.choice(upper), random.choice(lower), random.choice(digits), random.choice(symbols)]
    pool = lower + upper + digits + symbols
    
    while len(chars) < length:
        chars.append(random.choice(pool))
    random.shuffle(chars)
    return "".join(chars)

def run_cipher_toolkit():
    print("\n1) encrypt text")
    print("2) decrypt text")
    c = input("> ").strip()
    if c == "1":
        txt = input("text: ")
        k = ask_int("key (0-25): ")
        print("result ->", caesar_encrypt(txt, k))
    elif c == "2":
        txt = input("encrypted text: ")
        k = ask_int("key (0-25): ")
        print("result ->", caesar_decrypt(txt, k))
    else:
        print("invalid option")
        
def caesar_encrypt(text, key):
    out = ""
    for ch in text:
        out += shift_char(ch, key)
    return out

def caesar_decrypt(text, key):
    return caesar_encrypt(text, -key)

def shift_char(ch, key):
    if ch.islower():
        return ALPHA[(ALPHA.index(ch) + key) % 26]
    if ch.isupper():
        return ALPHA[(ALPHA.index(ch.lower()) + key) % 26].upper()
    return ch

def run_log_analyzer():
    path = input("\nlog file path (csv): ").strip()
    threshold = ask_int("suspicious attempts threshold (default 3): ", default=3)
    logs = parse_log_file(path)
    if not logs:
        print("no valid logs")
        return

    counts = count_failed_logins(logs)
    sus = flag_suspicious_ips(counts, threshold)
    print(f"\nrows analyzed: {len(logs)}")
    print(f"ips with at least one failure: {len(counts)}")
    if sus:
        print("suspicious ips:")
        for ip in sus:
            print(f" - {ip}: {sus[ip]} failed attempts")
    else:
        print("no suspicious ip with this threshold")

def parse_log_file(path):
    logs = []
    try:
        f = open(path, newline="", encoding="utf-8")
    except FileNotFoundError:
        print("file not found:", path)
        return logs

    reader = csv.DictReader(f)
    for row in reader:
        if is_valid_log_row(row):
            logs.append(row)
    f.close()
    return logs

def count_failed_logins(logs):
    counts = defaultdict(int)
    for row in logs:
        if row["status"].strip().lower() == "failed":
            ip = row["ip"].strip()
            counts[ip] += 1
    return dict(counts)

def flag_suspicious_ips(counts, threshold=3):
    result = {}
    for ip, n in counts.items():
        if n >= threshold:
            result[ip] = n
    return dict(sorted(result.items(), key=lambda x: x[1], reverse=True))

def is_valid_log_row(row):
    needed = ("timestamp", "ip", "status")
    for field in needed:
        if field not in row:
            return False

    if not row["ip"] or not row["status"]:
        return False

    try:
        datetime.fromisoformat(row["timestamp"])
    except ValueError:
        return False

    return True

if __name__ == "__main__":
    main()
