import json
import unittest

from Bip39 import BIP39
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
VECTORS = BASE_DIR / "test_vectors_bip39.json"


class TestBip39(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(VECTORS, encoding="utf-8") as f:
            cls.d = json.load(f)

    def test_seed_phrase_to_seed(self):
        for entropy_hex, mnemonic, seed_hex, xprv in self.d['english']:
            with self.subTest(mnemonic=mnemonic):
                bip39 = BIP39(seed_phrase_value=mnemonic.split())
                self.assertEqual(seed_hex, bip39.seed(passphrase='TREZOR').hex())

    def test_entropy_to_seed(self):
        for entropy_hex, mnemonic, seed_hex, xprv in self.d['english']:
            with self.subTest(entropy=entropy_hex):
                bip39 = BIP39(entropy=bytes.fromhex(entropy_hex))
                self.assertEqual(seed_hex, bip39.seed(passphrase='TREZOR').hex())

    def test_entropy_to_seed_phrase(self):
        for entropy_hex, mnemonic, seed_hex, xprv in self.d['english']:
            with self.subTest(entropy=entropy_hex):
                bip39 = BIP39(entropy=bytes.fromhex(entropy_hex))
                self.assertEqual(mnemonic, ' '.join(bip39.seed_phrase()))


if __name__ == '__main__':
    unittest.main()