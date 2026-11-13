# JoshTheRipper

Lightweight local password security auditing for Fedora Linux and other Python 3 systems.

**Scope:** Audit passwords you own or are authorized to test. This tool does not attempt password recovery, online login attacks, or bulk hash cracking.

## Install (Fedora)

```bash
sudo dnf install -y python3 git
python3 --version
python3 -m venv .venv
source .venv/bin/activate
```

No third-party Python packages are required.

## Usage

```bash
python3 joshtheripper.py
```

For exact matching against a SecLists password list, download SecLists separately:

```bash
git clone --depth 1 https://github.com/danielmiessler/SecLists.git
python3 joshtheripper.py --wordlist SecLists/Passwords/Common-Credentials/10k-most-common.txt
```

To verify a password you enter against a SHA-256 digest you already possess:

```bash
python3 joshtheripper.py --algorithm sha256 --hash YOUR_SHA256_HEX
```

For PBKDF2-SHA256 verification:

```bash
python3 joshtheripper.py --algorithm pbkdf2-sha256 --hash YOUR_HEX_DIGEST --salt-hex YOUR_HEX_SALT --iterations 600000
```

Export a report (password and hash values are never included):

```bash
python3 joshtheripper.py --wordlist SecLists/Passwords/Common-Credentials/10k-most-common.txt --report reports/audit.json
python3 joshtheripper.py --report reports/audit.txt
```

## Test

```bash
python3 -m unittest discover -s tests -v
```

## Security notes

- Password entry is hidden using `getpass`.
- Reports contain ratings, findings, and boolean results, not passwords or hashes.
- Wordlist matching checks exact entries; it does not generate guesses.
- Strength ratings are heuristic and not guarantees of safety.
- Legacy SHA-256/SHA-512 verification is for compatibility only; use salted adaptive password hashes in production.
- SecLists is a separate third-party project with its own license and maintenance. It is intentionally excluded from this repository.

## License

MIT. See LICENSE.
