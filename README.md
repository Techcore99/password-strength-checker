# 🔐 Password Strength Checker

A command-line tool that evaluates how strong a password is, built as part of my BSc Cyber Security studies.

## Features

* **Entropy calculation** based on length and character-set size
* **Pattern detection**: sequences (`abc`, `123`, `qwerty`), repeats (`aaa`), years
* **Common-password check**, including leetspeak variants (`P@ssw0rd`)
* **Crack-time estimate** for an offline attack (10 billion guesses/sec)
* **Breach check (optional)** using the [Have I Been Pwned](https://haveibeenpwned.com/API/v3#PwnedPasswords) API with *k-anonymity*, so only the first 5 characters of the SHA-1 hash are ever sent
* Hidden input via `getpass`, so the password isn't shown or stored
* Improvement tips and a unit-test suite

## Usage

```bash
python password\_checker.py            # offline check
python password\_checker.py --breach   # also check known breaches
python -m unittest discover tests     # run tests
```

Requires Python 3.8+ and no external libraries.

## Example

!\[Strong password demo](screenshots/demo.png)


!\[Weak password demo](screenshots/demo-weak.png)



```
  Strength : \[##---] Weak
  Length   : 11
  Entropy  : 72.1 bits (adjusted for patterns: 32.1 bits)
  Crack est: instantly (offline, 10B guesses/sec)
  Tips:
   - Use at least 12 characters (14+ is better).
   - Contains a common password - adding digits/symbols to it doesn't help.
   - Avoid sequences like 'abc', '123' or 'qwerty'.
```

## How it works

1. **Entropy** = `length × log2(pool size)`, where the pool is the sum of the character classes used (26 lower, 26 upper, 10 digits, 32 symbols).
2. **Penalties** reduce entropy for predictable patterns, since attackers try these first. Common passwords are capped at 10 bits.
3. **Score** (0-4) comes from the adjusted entropy: `<28` Very Weak, `<36` Weak, `<60` Fair, `<80` Strong, otherwise Very Strong.
4. **Crack time** = `2^entropy / guesses\_per\_second / 2` (on average, half the space is searched).

## Limitations

Entropy estimates are approximations; real attackers use dictionaries, rules and leaked-password lists. For better accuracy see [zxcvbn](https://github.com/dropbox/zxcvbn). Never type real passwords into tools you don't trust.

## Ideas for future work

* Larger wordlist (e.g. RockYou subset) and dictionary-word detection
* Passphrase generator
* Flask / web GUI
* Keyboard-walk detection beyond straight rows

## License

MIT

