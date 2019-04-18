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
    def header(self):
        return self._header

    @property
    def pdu(self):
        return self._pdu

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

    

    netkeys = [
        NetworkKey.fromString('604981DF5839F5A5A4025BBD768CEA6A', iv_index=0)
    ]

    def toStr(s):
        return ' '.join(map('{:02x}'.format, s))

    def PayloadDecode(s):
        total_len = len(s)
        i = 0
        packet_list = list()
        while i < total_len:
            packet_len = s[i]
            packet_type = s[i+1]
            packet_payload = s[i+2:i+packet_len+1]
            i += packet_len+1
            packet_list.append((packet_type, packet_payload))

        if i != total_len:
            print('i != total_len')
        return packet_list

    with MeshContext(netkeys=netkeys) as context:
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('192.168.113.250', 10010))
        f = sock.makefile()
        while True:
            l = f.readline()
            rssi, addr, data = eval(l)
            payloads = PayloadDecode(data)
            for payload in payloads:
                if payload[0] == 0x2a:
                    message = payload[1]
                    msg = NetworkMessage.from_bytes(message, ctx=context)
                    if msg is not None:
                        print(msg.header.ttl, msg.header.seq, '%04x' % msg.header.src, '%04x' % msg.pdu.dst)
