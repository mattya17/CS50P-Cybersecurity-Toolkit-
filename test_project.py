import csv, os
from project import (
    check_password_strength,
    has_common_pattern,
    generate_secure_password,
    caesar_encrypt,
    caesar_decrypt,
    parse_log_file,
    count_failed_logins,
    flag_suspicious_ips,
)

def test_check_password_strength():
    score, notes = check_password_strength("abc")
    assert score == 0
    assert len(notes) > 0
    score2, notes2 = check_password_strength("Xk9$vLp2#QzT")
    assert score2 == 5
    assert notes2 == ["great password!"]

def test_has_common_pattern():
    assert has_common_pattern("password")
    assert has_common_pattern("abc123")
    assert not has_common_pattern("Xk9$vLp2#QzT")

def test_generate_secure_password():
    pw = generate_secure_password(16)
    assert len(pw) == 16
    assert any(c.isupper() for c in pw)
    assert any(c.isdigit() for c in pw)
    pw2 = generate_secure_password(4)
    assert len(pw2) == 8

def test_caesar_encrypt():
    assert caesar_encrypt("abc", 1) == "bcd"
    assert caesar_encrypt("xyz", 3) == "abc"
    assert caesar_encrypt("Hello, World!", 5) == "Mjqqt, Btwqi!"

def test_caesar_decrypt():
    assert caesar_decrypt("bcd", 1) == "abc"
    assert caesar_decrypt("abc", 3) == "xyz"
    assert caesar_decrypt(caesar_encrypt("Hello everyone!", 7), 7) == "Hello everyone!"

def test_count_failed_logins():
    logs = [
        {"timestamp": "2026-07-01T10:00:00", "ip": "1.1.1.1", "status": "failed"},
        {"timestamp": "2026-07-01T10:01:00", "ip": "1.1.1.1", "status": "failed"},
        {"timestamp": "2026-07-01T10:02:00", "ip": "2.2.2.2", "status": "success"},
        {"timestamp": "2026-07-01T10:03:00", "ip": "1.1.1.1", "status": "success"},
    ]
    result = count_failed_logins(logs)
    assert result == {"1.1.1.1": 2}
    
def test_flag_suspicious_ips():
    counts = {"1.1.1.1": 5, "2.2.2.2": 1, "3.3.3.3": 3}
    result = flag_suspicious_ips(counts, threshold=3)
    assert result == {"1.1.1.1": 5, "3.3.3.3": 3}
    result2 = flag_suspicious_ips(counts, threshold=10)
    assert result2 == {}

def test_parse_log_file():
    path = "test_log_temp.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "ip", "status"])
        writer.writerow(["2026-07-01T10:00:00", "1.1.1.1", "failed"])
        writer.writerow(["not-a-date", "2.2.2.2", "failed"])
        writer.writerow(["2026-07-01T10:02:00", "3.3.3.3", "success"])
    logs = parse_log_file(path)
    os.remove(path)
    assert len(logs) == 2
    assert logs[0]["ip"] == "1.1.1.1"
