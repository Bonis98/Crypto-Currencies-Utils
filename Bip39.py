import argparse
from hashlib import sha256
from hashlib import pbkdf2_hmac
import secrets

class BIP39:
    def __init__(self, entropy=128, seedphrase=None):
        self.seedPhrase=seedphrase
        if seedphrase is not None:
            if not self.__isphrasevalid(seedphrase):
                raise Exception('Invalid seedphrase')
        else:
            #If a seedphrase is used, the entropy is set in the validation phase
            if entropy not in [128, 160, 192, 224, 256]:
                raise Exception("Entropy value must be one of 128, 160, 192, 224, 256 ")
            self.entropy = entropy

    def seedphrase(self):
        # Create entropy
        random = secrets.randbits(self.entropy).to_bytes(length=int(self.entropy / 8))
        # Calculate digest
        digest = sha256(random).hexdigest()
        # Calculate checksum of entropy
        CS = ''.join(f'{byte:08b}' for byte in bytes.fromhex(digest))[:int((self.entropy / 32))]
        # Concatenate entropy and checksum
        binmnemonic = ''.join(f'{byte:08b}' for byte in random) + CS
        #Split mnemonic into groups of 11 bits
        splitbinmnemonic = [binmnemonic[i:i + 11] for i in range(0, len(binmnemonic), 11)]
        #Load wordlist
        words = self.__loadWordList('wordlist/english_wordlist.txt')
        seedphrase = []
        #for each group of bits, find the correspondent word
        for group in splitbinmnemonic:
            index = int(group, 2)
            seedphrase.append(words[index])
        if self.__isphrasevalid(seedphrase):
            self.seedPhrase = seedphrase
        else:
            raise Exception("Generic error")
        return seedphrase

    def seed(self, passphrase=''):
        # Concatenate words
        password = ' '.join(self.seedPhrase).encode()
        # Concatenate passphrase
        passphrase = 'mnemonic' + passphrase
        key = pbkdf2_hmac(hash_name='sha512', password=password, salt=passphrase.encode(), iterations=2048, dklen=64)
        return key

    def __isphrasevalid(self, seedphrase):
        words = self.__loadWordList('wordlist/english_wordlist.txt')
        indexs = []
        binmnemonic = ''
        for group in seedphrase:
            indexs.append(words.index(group))
        for index in indexs:
            binmnemonic += "{:>011}".format(bin(index)[2:])
        # Extract checksum from mnemonic
        CS = binmnemonic[-len(binmnemonic)//32+1:]
        # Extract random from mnemonic
        random = binmnemonic[:-len(binmnemonic)//32+1]
        self.entropy = len(random)
        digest = sha256(int(random,2).to_bytes(length=int(self.entropy / 8))).hexdigest()
        # Calculate checksum of entropy
        calculatedCS = ''.join(f'{byte:08b}' for byte in bytes.fromhex(digest))[:int((self.entropy / 32))]
        return calculatedCS == CS


    @staticmethod
    def __loadWordList(filename):
        words = []
        with open(filename, "r") as f:
            for line in f.readlines():
                words.append(line[:-1])
        return words