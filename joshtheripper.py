#!/usr/bin/env python3
"""JoshTheRipper: local, consent-based password auditing."""
import argparse
import getpass
import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_LIST = Path('SecLists/Passwords/Common-Credentials/10k-most-common.txt')


def strength(password):
    score = 0
    findings = []
    length = len(password)
    if length >= 16:
        score += 3
    elif length >= 12:
        score += 2
    elif length >= 8:
        score += 1
    else:
        findings.append('Password is shorter than 8 characters')
    classes = sum(bool(re.search(pattern, password)) for pattern in (r'[a-z]', r'[A-Z]', r'\d', r'[^\w\s]'))
    score += min(classes, 3)
    if re.search(r'(.)\1{2,}', password):
        score -= 2
        findings.append('Contains repeated characters')
    if re.search(r'(1234|abcd|qwerty|password|letmein|admin)', password, re.I):
        score -= 3
        findings.append('Contains a predictable sequence or phrase')
    if length < 12:
        findings.append('Consider using a unique passphrase of at least 12 characters')
    rating = 'strong' if score >= 5 and length >= 12 else 'moderate' if score >= 3 else 'weak'
    return {'rating': rating, 'length': length, 'findings': findings}


def wordlist_match(password, path):
    """Exact matches only; no guessing or candidate generation."""
    if not path.exists():
        raise FileNotFoundError(f'Wordlist not found: {path}')
    with path.open('r', encoding='utf-8', errors='replace') as stream:
        for line in stream:
            if hmac.compare_digest(line.rstrip('\r\n').encode(), password.encode()):
                return True
    return False


def verify_hash(password, expected, algorithm, salt=None, iterations=600000):
    if algorithm in ('sha256', 'sha512'):
        if not re.fullmatch(r'[0-9a-fA-F]+', expected):
            raise ValueError('Hash must be hexadecimal')
        digest = hashlib.new(algorithm, password.encode()).hexdigest()
    elif algorithm == 'pbkdf2-sha256':
        if salt is None:
            raise ValueError('--salt-hex is required for PBKDF2')
        digest = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), iterations).hex()
    else:
        raise ValueError('Unsupported hash algorithm')
    return hmac.compare_digest(digest, expected.lower())


def save_report(report, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.suffix.lower() == '.json':
        destination.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    elif destination.suffix.lower() == '.txt':
        lines = ['JoshTheRipper audit report', f"Timestamp: {report['timestamp']}", f"Rating: {report['strength']['rating']}", f"Length: {report['strength']['length']}"]
        lines += [f'Finding: {finding}' for finding in report['strength']['findings']]
        for key in ('wordlist_match', 'hash_verified'):
            if key in report:
                lines.append(f'{key}: {report[key]}')
        destination.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    else:
        raise ValueError('Report filename must end in .json or .txt')


def main():
    parser = argparse.ArgumentParser(description='JoshTheRipper: local password auditing')
    parser.add_argument('--wordlist', type=Path, help='Check exact password against this local wordlist')
    parser.add_argument('--hash', dest='expected_hash', help='Verify entered password against this supplied hash')
    parser.add_argument('--algorithm', choices=['sha256', 'sha512', 'pbkdf2-sha256'], default='sha256')
    parser.add_argument('--salt-hex', help='Hexadecimal salt for PBKDF2')
    parser.add_argument('--iterations', type=int, default=600000)
    parser.add_argument('--report', type=Path, help='Save redacted .json or .txt report')
    args = parser.parse_args()
    if args.iterations < 1:
        parser.error('--iterations must be positive')
    if args.expected_hash and args.algorithm == 'pbkdf2-sha256' and not args.salt_hex:
        parser.error('--salt-hex is required for PBKDF2 verification')
    print('=== JoshTheRipper | Local Password Audit ===')
    password = getpass.getpass('Enter a password you own (hidden): ')
    try:
        report = {'tool': 'JoshTheRipper', 'timestamp': datetime.now(timezone.utc).isoformat(), 'strength': strength(password)}
        if args.wordlist:
            report['wordlist_match'] = wordlist_match(password, args.wordlist)
        if args.expected_hash:
            report['hash_verified'] = verify_hash(password, args.expected_hash, args.algorithm, args.salt_hex, args.iterations)
        print(json.dumps(report, indent=2))
        if args.report:
            save_report(report, args.report)
            print(f'Report saved: {args.report}')
    except (OSError, ValueError) as exc:
        parser.exit(1, f'Error: {exc}\n')


if __name__ == '__main__':
    main()
