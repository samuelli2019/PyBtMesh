#!/bin/env python3

import operator
import bitstring
from Util import *

class ApplicationMessage:
    pass

def network_nounce(ctl, ttl, src, seq, iv_index):
    return bitstring.pack('uint:8, uint:1, uint:7, uintbe:24, uintbe:16, pad:16, uintbe:32',
                            0x00, ctl, ttl, seq, src, iv_index).bytes

class NetworkHeader:
    NETWORK_HEADER_STRUCT = 'uint:1, uint:7, uintbe:24, uintbe:16'
    def __init__(self, ctl, ttl, seq, src):
        self._ctl = ctl
        self._ttl = ttl
        self._seq = seq
        self._src = src

    @property
    def ctl(self):
        return self._ctl
    
    @property
    def ttl(self):
        return self._ttl

    @property
    def seq(self):
        return self._seq

    @property
    def src(self):
        return self._src

    @classmethod
    def from_bytes(cls, b):
        ctl, ttl, seq, src = bitstring.BitStream(b).unpack(cls.NETWORK_HEADER_STRUCT)
        return cls(ctl, ttl, seq, src)
    
    def to_bytes(self):
        return bitstring.pack(self.NETWORK_HEADER_STRUCT, self.ctl, self.ttl, self.seq, self.src).bytes

class NetworkEncryptedData:
    NETWORK_ENCRYPTED_STRUCT = 'uintbe:16, bytes'
    def __init__(self, dst, pdu):
        self._dst = dst
        self._pdu = pdu
    
    @property
    def dst(self):
        return self._dst

    @property
    def pdu(self):
        return self._pdu

    @classmethod
    def from_bytes(cls, b):
        dst, pdu = bitstring.BitStream(b).unpack(cls.NETWORK_ENCRYPTED_STRUCT)
        return cls(dst, pdu)

    def to_bytes(self):
        return bitstring.pack(self.NETWORK_ENCRYPTED_STRUCT, self.dst, self.pdu).bytes

class NetworkMessage:
    NETWORK_MESSAGE_STRUCT = 'uint:1, uint:7, bytes:6, bytes'
    def __init__(self, header, pdu, ctx, netkey_index=0):
        self._ctx = ctx
        self._netkey_index = netkey_index
        self._header = header
        self._pdu = pdu
        self._netkey_index = netkey_index

    @property
    def key_index(self):
        return self._netkey_index

    @classmethod
    def from_bytes(cls, b, ctx):
        iv_check, nid, header, pdu_mic = bitstring.BitStream(b).unpack(cls.NETWORK_MESSAGE_STRUCT)
        for i, key in enumerate(ctx.netkeys):
            # fast check
            if iv_check == key.iv_index & 0x01 and nid == key.nid & 0x7f:
                privacy_random = bitstring.pack('pad:40, uintbe:32, bytes:7', key.iv_index, pdu_mic[:7]).bytes
                pecb = aes_ecb(key.privacy_key, privacy_random)[:6]
                raw_header = bytes(map(operator.xor, header, pecb))
                h = NetworkHeader.from_bytes(raw_header)
                if h.ctl == 1:
                    # Control Message
                    tag_len = 8
                else:
                    # Access Message
                    tag_len = 4
                raw_netpdu = aes_ccm_decrypt(key.encrypt_key, network_nounce(h.ctl, h.ttl, h.src, h.seq, key.iv_index), pdu_mic, tag_length=tag_len)
                epdu = NetworkEncryptedData.from_bytes(raw_netpdu)
                return cls(h, epdu, ctx, i)
        else:
            return None

    def to_bytes(self):
        return bitstring.pack(self.NETWORK_MESSAGE_STRUCT, 
            self._ctx.netkeys[self._netkey_index].iv_index & 0x01,
            self._ctx.netkeys[self._netkey_index].nid & 0x7f,
            self._header.to_bytes(),
            self._pdu.to_bytes()
        )

class UnProvisionedBeacon:
    pass

class ProvisionedBeacon:
    pass

if __name__ == "__main__":
    from Context import *
    from Util import *

    message = bytes.fromhex('68eca487516765b5e5bfdacbaf6cb7fb6bff871f035444ce83a670df')

    netkeys = [
        NetworkKey.fromString('7dd7364cd842ad18c17c2b820c84c3d6', iv_index=0x12345678)
    ]
    with MeshContext(netkeys=netkeys) as context:
        msg = NetworkMessage.from_bytes(message, ctx=context)
        print(msg.to_bytes().hex)
