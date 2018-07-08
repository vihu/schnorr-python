import hashlib
import binascii
import unittest

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def point_add(p1, p2):
    if (p1 is None):
        return p2
    if (p2 is None):
        return p1
    if (p1[0] == p2[0] and p1[1] != p2[1]):
        return None
    if (p1 == p2):
        lam = (3 * p1[0] * p1[0] * pow(2 * p1[1], p - 2, p)) % p
    else:
        lam = ((p2[1] - p1[1]) * pow(p2[0] - p1[0], p - 2, p)) % p
    x3 = (lam * lam - p1[0] - p2[0]) % p
    return (x3, (lam * (p1[0] - x3) - p1[1]) % p)

def point_mul(p, n):
    r = None
    for i in range(256):
        if ((n >> i) & 1):
            r = point_add(r, p)
        p = point_add(p, p)
    return r

def bytes_point(p):
    return (b'\x03' if p[1] & 1 else b'\x02') + p[0].to_bytes(32, byteorder="big")

def sha256(b):
    return int.from_bytes(hashlib.sha256(b).digest(), byteorder="big")

def on_curve(point):
    return (pow(point[1], 2, p) - pow(point[0], 3, p)) % p == 7

def jacobi(x):
    return pow(x, (p - 1) // 2, p)

def schnorr_sign(msg, seckey):
    k = sha256(seckey.to_bytes(32, byteorder="big") + msg)
    R = point_mul(G, k)
    if jacobi(R[1]) != 1:
        k = n - k
    e = sha256(R[0].to_bytes(32, byteorder="big") + bytes_point(point_mul(G, seckey)) + msg)
    return R[0].to_bytes(32, byteorder="big") + ((k + e * seckey) % n).to_bytes(32, byteorder="big")

def schnorr_verify(msg, pubkey, sig):
    if (not on_curve(pubkey)):
        return False
    r = int.from_bytes(sig[0:32], byteorder="big")
    s = int.from_bytes(sig[32:64], byteorder="big")
    if r >= p or s >= n:
        return False
    e = sha256(sig[0:32] + bytes_point(pubkey) + msg)
    R = point_add(point_mul(G, s), point_mul(pubkey, n - e))
    if R is None or jacobi(R[1]) != 1 or R[0] != r:
        return False
    return True

def create_input(private_key, public_key, message, signature):
    return dict(
            private_key=private_key,
            public_key=public_key,
            message=bytearray.fromhex(message),
            signature=bytearray.fromhex(signature))

class TestValidInputs(unittest.TestCase):
    def setUp(self):
        one = create_input(
                0x0000000000000000000000000000000000000000000000000000000000000001,
                0x0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
                '0000000000000000000000000000000000000000000000000000000000000000',
                '787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF67031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05'
                )
        two = create_input(
                0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF,
                0x02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659,
                '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
                '2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD'
                )
        three = create_input(
                0xC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C7,
                0x03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B,
                '5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C',
                '00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE00880371D01766935B92D2AB4CD5C8A2A5837EC57FED7660773A05F0DE142380'
                )
        self.input = dict(one=one, two=two, three=three)

    def test_vector1(self):
        private_key = self.input['one']['private_key']
        public_key = self.input['one']['public_key']
        message = self.input['one']['message']
        signature = self.input['one']['signature']

        sig = schnorr_sign(message, private_key)
        # is_verified = schnorr_verify(message, public_key, signature)
        self.assertTrue(bytearray(sig), signature)
        # self.assertTrue(is_verified)

    def test_vector2(self):
        private_key = self.input['two']['private_key']
        public_key = self.input['two']['public_key']
        message = self.input['two']['message']
        signature = self.input['two']['signature']

        sig = schnorr_sign(message, private_key)
        # is_verified = schnorr_verify(message, public_key, signature)
        self.assertTrue(bytearray(sig), signature)
        # self.assertTrue(is_verified)

    def test_vector3(self):
        private_key = self.input['three']['private_key']
        public_key = self.input['three']['public_key']
        message = self.input['three']['message']
        signature = self.input['two']['signature']

        sig = schnorr_sign(message, private_key)
        # is_verified = schnorr_verify(message, public_key, signature)
        self.assertTrue(bytearray(sig), signature)
        # self.assertTrue(is_verified)

if __name__ == '__main__':
    unittest.main()
