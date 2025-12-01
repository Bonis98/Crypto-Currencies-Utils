# Crypto-Currencies-Utils

Crypto-Currencies-Utils is an educational Python project implementing basic cryptocurrency functionality focused on Bitcoin standards **BIP39** and **BIP32**.

## Overview

This project is purely for learning purposes. It lets you generate entropy and convert it into a seed phrase (BIP39), and derive Bitcoin keys and addresses from a seed (BIP32).  
Despite including tests, these classes are **not recommended for real use** as bugs could lead to loss of funds.

## Requirements

- Python 3.8+
- External libraries: `ecdsa`, `base58`

## Installation

```bash
git clone https://github.com/Bonis98/Crypto-Currencies-Utils.git
cd Crypto-Currencies-Utils
pip install ecdsa base58
```

## Usage

### BIP39 - Generate Seed Phrase
```python
from Bip39 import BIP39

wallet = BIP39(entropy_bits=256)
seedPhrase = wallet.seedphrase()
print('BIP39 Phrase:', ' '.join(seedPhrase))
print('Seed:', wallet.seed().hex())
```

### BIP32 - Master Key Derivation (Work in Progress)
```python
from BIP32 import Master_node

master = Master_node(seed)
print(master.public_key().hex())  # Compressed public key
print(master.extended_key(type="private").decode())  # Extended private key (base58)
```

## Project Status

- BIP39: Fully implemented entropy generation and mnemonic conversion.
- BIP32: Master key generation, public key compression, and extended key serialization done. Child key derivation is in progress.

## Contributions

Contributions welcome! Send pull requests and report bugs.

## License

MIT License

---

**Warning:** This project is for educational purposes only. Using these classes in real wallets may cause fund loss due to possible bugs.
