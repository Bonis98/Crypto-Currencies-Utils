import unittest
from BIP32 import Master_node

class TestBip32(unittest.TestCase):

    def test_master_keys(self):
        test_vector_1 = Master_node(seed=bytes.fromhex('000102030405060708090a0b0c0d0e0f'))
        self.assertEqual(test_vector_1.extended_key(type='private').decode(), 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3w'
                                                                             'JUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJx'
                                                                             'WUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi')
        self.assertEqual(test_vector_1.extended_key(type='public').decode(), 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLm'
                                                                            'C4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Ru'
                                                                            'pje8YtGqsefD265TMg7usUDFdp6W1EGMcet8')

        test_vector_2 = Master_node(seed=bytes.fromhex('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5'
                                                      'a29f9c999693908d8a8784817e7b7875726f6c696663605d5a57545'
                                                      '14e4b484542'))
        self.assertEqual(test_vector_2.extended_key(type='private').decode(), 'xprv9s21ZrQH143K31xYSDQpPDxsXRTUc'
                                                                             'vj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4P'
                                                                             'FmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U')
        self.assertEqual(test_vector_2.extended_key(type='public').decode(), 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2P'
                                                                            'St5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Z'
                                                                            'z8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB')

        test_vector_3 = Master_node(seed=bytes.fromhex('4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4a'
                                                      'cba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73'
                                                      '235be'))
        self.assertEqual(test_vector_3.extended_key(type='private').decode(), 'xprv9s21ZrQH143K25QhxbucbDDuQ4naN'
                                                                             'ntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8p'
                                                                             'h3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6')
        self.assertEqual(test_vector_3.extended_key(type='public').decode(), 'xpub661MyMwAqRbcEZVB4dScxMAdx6d4nF'
                                                                            'c9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6S'
                                                                            'zXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13')

        test_vector_4 = Master_node(seed=bytes.fromhex('3ddd5602285899a946114506157c7997e5444528f3003f613'
                                                      '4712147db19b678'))
        self.assertEqual(test_vector_4.extended_key(type='private').decode(), 'xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ'
                                                                             '3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvs'
                                                                             'vNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv')
        self.assertEqual(test_vector_4.extended_key(type='public').decode(), 'xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW'
                                                                            '1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmg'
                                                                            'BUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa')

if __name__ == '__main__':
    unittest.main()
