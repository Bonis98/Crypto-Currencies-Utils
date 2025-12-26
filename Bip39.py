import unicodedata
from hashlib import sha256
from hashlib import pbkdf2_hmac
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
WORDLIST_PATH = BASE_DIR / "wordlist" / "english_wordlist.txt"

class BIP39:
    def __init__(self, entropy_bits: int=128, seed_phrase_value: list[str]=None, entropy: bytes=None):
        if seed_phrase_value is not None and entropy is not None:
            raise Exception("Only one of entropy or seed_phrase_value must be specified")
        if seed_phrase_value is not None:
            if not self.__isphrasevalid(seed_phrase_value):
                raise ValueError('Invalid seedphrase')
            else:
                self.seed_phrase_value = seed_phrase_value
        else:
            #If a seedphrase is used, the entropy is set in the validation phase
            self.seed_phrase_value = None
            if entropy_bits not in [128, 160, 192, 224, 256]:
                raise Exception("Entropy value must be one of 128, 160, 192, 224, 256 ")
            self.entropy_bits = entropy_bits
            self.entropy = entropy
        if entropy is not None:
            self.entropy_bits = len(entropy)*8

    def seed_phrase(self):
        if self.seed_phrase_value is not None:
            return self.seed_phrase_value
        if self.entropy is None:
            # Create entropy
            self.entropy = secrets.randbits(self.entropy_bits).to_bytes(length=int(self.entropy_bits / 8))
        # Calculate digest
        digest = sha256(self.entropy).hexdigest()
        # Calculate checksum of entropy
        CS = ''.join(f'{byte:08b}' for byte in bytes.fromhex(digest))[:int((self.entropy_bits / 32))]
        # Concatenate entropy and checksum
        bin_mnemonic = ''.join(f'{byte:08b}' for byte in self.entropy) + CS
        #Split mnemonic into groups of 11 bits
        split_bin_mnemonic = [bin_mnemonic[i:i + 11] for i in range(0, len(bin_mnemonic), 11)]
        #Load wordlist
        words = self.__loadWordList('wordlist/english_wordlist.txt')
        seed_phrase_value = []
        #for each group of bits, find the correspondent word
        for group in split_bin_mnemonic:
            index = int(group, 2)
            seed_phrase_value.append(words[index])
        if self.__isphrasevalid(seed_phrase_value):
            self.seed_phrase_value = seed_phrase_value
        else:
            raise Exception("Generic error")
        return seed_phrase_value

    def seed(self, passphrase=''):
        seed_phrase_value = self.seed_phrase()
        # Concatenate words
        password = unicodedata.normalize('NFKD', ' '.join(seed_phrase_value))
        # Concatenate passphrase
        passphrase = 'mnemonic' + unicodedata.normalize('NFKD', passphrase)
        key = pbkdf2_hmac(hash_name='sha512',
                          password=password.encode(),
                          salt=passphrase.encode(),
                          iterations=2048,
                          dklen=64)
        return key

    def __isphrasevalid(self, seed_phrase):
        words = self.__loadWordList('wordlist/english_wordlist.txt')
        indexs = []
        binmnemonic = ''
        for group in seed_phrase:
            indexs.append(words.index(group))
        for index in indexs:
            binmnemonic += "{:>011}".format(bin(index)[2:])
        # Extract checksum from mnemonic
        CS = binmnemonic[-len(binmnemonic)//32+1:]
        # Extract entropy from mnemonic
        entropy = binmnemonic[:-len(binmnemonic)//32+1]
        self.entropy_bits = len(entropy)
        self.entropy = int(entropy, 2).to_bytes(length=self.entropy_bits//8)
        digest = sha256(int(entropy,2).to_bytes(length=int(self.entropy_bits / 8))).hexdigest()
        # Calculate checksum of entropy
        calculatedCS = ''.join(f'{byte:08b}' for byte in bytes.fromhex(digest))[:int((self.entropy_bits / 32))]
        return calculatedCS == CS


    @staticmethod
    def __loadWordList(filename):
        words = []
        with open(WORDLIST_PATH, "r") as f:
            for line in f.readlines():
                words.append(line[:-1])
        return words