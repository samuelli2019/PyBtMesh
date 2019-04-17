import unittest
import Util

class TestUtil(unittest.TestCase):
    def test_init(self):
        pass

    def test_s1(self):
        self.assertEqual(Util.s1(b'test'), bytes.fromhex('b73cefbd641ef2ea598c2b6efb62f79c'))

    def test_k1(self):
        N = bytes.fromhex('3216d1509884b533248541792b877f98')
        SALT = bytes.fromhex('2ba14ffa0df84a2831938d57d276cab4')
        P = bytes.fromhex('5a09d60797eeb4478aada59db3352a0d')
        self.assertEqual(Util.k1(N, SALT, P), bytes.fromhex('f6ed15a8934afbe7d83e8dcb57fcf5d7'))

    def test_k2(self):
        N = bytes.fromhex('f7a2a44f8e8a8029064f173ddc1e2b00')
        P = bytes.fromhex('00')
        n, e, p = Util.k2(N, P)
        self.assertEqual(n, 0x7f)
        self.assertEqual(e, bytes.fromhex('9f589181a0f50de73c8070c7a6d27f46'))
        self.assertEqual(p, bytes.fromhex('4c715bd4a64b938f99b453351653124f'))

    def test_k3(self):
        N = bytes.fromhex('f7a2a44f8e8a8029064f173ddc1e2b00')
        self.assertEqual(Util.k3(N), bytes.fromhex('ff046958233db014'))

    def test_k4(self):
        N = bytes.fromhex('3216d1509884b533248541792b877f98')
        self.assertEqual(Util.k4(N), 0x38)

    def test_appkey(self):
        appkey = Util.ApplicationKey(bytes.fromhex('63964771734fbd76e3b40519d1d94a48'))
        self.assertEqual(appkey.aid, 0x26)

    def test_netkey(self):
        netkey = Util.NetworkKey.fromString('7dd7364cd842ad18c17c2b820c84c3d6', iv_index=0)
        self.assertEqual(netkey.nid, 0x68)
        self.assertEqual(netkey.encrypt_key, bytes.fromhex('0953fa93e7caac9638f58820220a398e'))
        self.assertEqual(netkey.privacy_key, bytes.fromhex('8b84eedec100067d670971dd2aa700cf'))
        self.assertEqual(netkey.network_id, bytes.fromhex('3ecaff672f673370'))
        self.assertEqual(netkey.identity_key, bytes.fromhex('84396c435ac48560b5965385253e210c'))
        self.assertEqual(netkey.beacon_key, bytes.fromhex('5423d967da639a99cb02231a83f7d254'))

if __name__ == "__main__":
    unittest.main()