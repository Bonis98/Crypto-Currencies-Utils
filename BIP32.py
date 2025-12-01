from abc import ABC, abstractmethod
from hashlib import sha256
from hmac import HMAC

from base58 import b58encode
from ecdsa import SECP256k1, SigningKey

n = SECP256k1.order
G = SECP256k1.generator

version = {
    'mainnet': {
        'private': "0488ADE4",
        'public': "0488B21E",
    },
    'testnet': {
        'private': "04358394",
        'public': "043587CF"
    }
}


class Node(ABC):
    def __init__(self, net: str = 'mainnet'):
        self.key = None
        self.chain = None
        if net not in {'mainnet', 'testnet'}:
            raise ValueError(f"{self.__class__.__name__}: net must be one of %r." % {'mainnet', 'testnet'})
        self.net = net

    @abstractmethod
    def public_key(self):
        """Return the compressed public key bytes."""
        pass

    @abstractmethod
    def extended_key(self, type: str = 'private'):
        """Return the extended key in base58 format bytes."""
        pass


class Master_node(Node):
    def __init__(self, seed: bytes, net: str = 'mainnet'):
        super().__init__(net)
        digest = HMAC(key=b'Bitcoin seed', msg=seed, digestmod='SHA512').digest()
        key = digest[:32]
        if int.from_bytes(key) == 0 or int.from_bytes(key) >= n:
            raise Exception("Generic error")
        self.key = key
        self.chain = digest[32:]

    def public_key(self) -> bytes:
        priv_key = SigningKey.from_string(self.key, curve=SECP256k1)
        pub_key = priv_key.get_verifying_key()
        x = pub_key.pubkey.point.x()
        y = pub_key.pubkey.point.y()
        prefix = b'\x02' if y % 2 == 0 else b'\x03'
        pub_compressed = prefix + x.to_bytes(32, 'big')

        return pub_compressed

    def extended_key(self, type: str = 'private') -> bytes:
        if type not in {'private', 'public'}:
            raise ValueError("calculateextendedkey: net must be one of %r." % {'private', 'public'})
        serialization = bytes.fromhex(version[self.net][type])
        serialization += b'\x00'
        serialization += b'\x00\x00\x00\x00'
        serialization += b'\x00\x00\x00\x00'
        serialization += self.chain
        if type == 'private':
            serialization += b'\x00'
            serialization += self.key
        else:
            pub_key = self.public_key()
            serialization += pub_key

        digest1 = sha256(serialization).digest()
        digest2 = sha256(digest1).digest()

        serialization += digest2[:4]

        private_key_base58 = b58encode(serialization)
        return private_key_base58
