# Password Strength Checker

A command-line password strength checker written in Python. It scores a password from 0 to 4, detects weak patterns, and can check whether the password has appeared in a known data breach. It uses only the Python standard library.

## Features

- Checks length and character types (uppercase, lowercase, digits, special characters)
- Detects common passwords, sequences, repeated characters, keyboard patterns, leetspeak, dictionary words, personal information, and year or date patterns
- Calculates entropy, a score from 0 (Very Weak) to 4 (Very Strong), and an offline crack-time estimate
- Optional breach check using the Have I Been Pwned range API with k-anonymity (only the first 5 characters of the SHA-1 hash are sent)
- Gives suggestions to improve the password
- Generates secure passwords and passphrases
- Hidden password input; the password is never stored or logged

## Requirements

- Python 3
- No external libraries

## Usage

```
python password_strength_checker.py
```

Choose an option from the menu: check a password, generate a password, generate a passphrase, or exit.

## How scoring works

Entropy is estimated as `length × log2(character set size)`. Penalties are subtracted for weak patterns such as sequences, keyboard walks, dictionary words, and personal information. Common or breached passwords are rated Very Weak.

## Python modules used

| Module | Purpose |
| --- | --- |
| `getpass` | Hidden password input |
| `hashlib` | SHA-1 hash for the breach check |
| `math` | `log2()` for entropy |
| `re` | Pattern matching |
| `secrets` | Secure random generation |
| `string` | Character sets |
| `urllib.request` | HTTPS request to the breach API |

## Limitations

The built-in common-password and dictionary lists are small and meant for demonstration. A larger wordlist would improve detection.

## Author

Kaish ([@kaishkhan07](https://github.com/kaishkhan07))
