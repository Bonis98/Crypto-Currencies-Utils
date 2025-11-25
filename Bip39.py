import argparse
import hashlib
import secrets

def bitsToWords(bits):
    words = []
    with open("english_wordlist.txt", "r") as f:
        for line in f.readlines():
            words.append(line[:-1])
    seedPhrase = []
    for group in bits:
        index = int(group, 2)
        seedPhrase.append(words[index])
    return seedPhrase

if __name__ == '__main__':
    # CLI
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--entropy", type=int, default=128, choices=[128, 160, 192, 224, 256])
    args = parser.parse_args()

    #Create entropy
    entropy = args.entropy
    random = secrets.randbits(entropy).to_bytes(length=int(entropy/8))
    print('Entropy:' + random.hex())
    #Calculate digest
    digest = hashlib.sha256(random).hexdigest()
    print('Hash of entropy:' + digest)
    #Calculate checksum of entropy
    CS = ''.join(f'{byte:08b}' for byte in bytes.fromhex(digest))[:int((entropy/32))]
    print('Checksum of entropy: ' + hex(int(CS, 2)))
    #Concatenate entropy and checksum
    MS = ''.join(f'{byte:08b}' for byte in random) + CS
    print('Mnemonic sentence:' + hex(int(MS, 2)))
    #Split mnemonic into groups of 11 bits
    splitMS = [MS[i:i+11] for i in range(0, len(MS), 11)]
    print('Seed length: ' + str(len(splitMS)))
    #Map groups into words
    seedPhrase = bitsToWords(splitMS)
    print('Seed Phrase: ' + ' '.join(seedPhrase))
