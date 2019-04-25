#!/bin/env python3

import operator
import uuid
import bitstring
from Util import *

class Message:
    MESSAGE_STRUCT = 'uint:8, bytes'
    MESH_PBADV = 0x29
    MESH_MESSAGE = 'Mesh Messages'
    MESH_BEACON = 'Mesh Network Beacon'

    @classmethod
    def from_bytes(cls, data):
        msg_type, pdu = bitstring.BitStream(data).unpack(cls.MESSAGE_STRUCT)
        if msg_type == cls.MESH_PBADV:
            return MeshPBADV.from_bytes(pdu)
        elif msg_type == cls.MESH_MESSAGE:
            return MeshMessage.from_bytes(pdu)
        elif msg_type == cls.MESH_BEACON:
            return MeshBeacon.from_bytes(pdu)
        else:
            return None

class MeshPBADV:
    MESSAGE_STRUCT = ''
    @classmethod
    def from_bytes(cls, data):
        pass

class MeshMessage:
    MESSAGE_STRUCT = ''
    @classmethod
    def from_bytes(cls, data):
        pass

class MeshBeacon:
    MESSATE_STRUCT = ''
    @classmethod
    def from_bytes(cls, data):
        pass

class MessageType:
    UnSegmentControlMessage = 'UnSegmentControlMessage'
    SegmentControlMessage = 'SegmentControlMessage'
    UnSegmentAccessMessage = 'UnSegmentAccessMessage'
    SegmentAccessMessage = 'SegmentAccessMessage'

class ControlMessage:
    def __init__(self):
        pass

    @classmethod
    def from_bytes(self, data):
        pass

class SegmentControlMessage:
    def __init__(self):
        pass

    def append_segment(self, segment):
        pass

class AccessMessage:
    MESSAGE_STRUCT = 'pad:1, uint:1, uint:6, bytes'
    def __init__(self, akf, aid, pdu):
        self._akf = akf
        self._aid = aid
        self._pdu = pdu

    @classmethod
    def from_bytes(cls, data):
        akf, aid, pdu = bitstring.BitStream(data).unpack(cls.MESSAGE_STRUCT)
        print(akf, aid, pdu)
        return cls(akf, aid, pdu)

class SegmentAccessMessage:
    def __init__(self):
        pass

    def append_segment(self, segment):
        pass



class NetworkHeader:
    NETWORK_HEADER_STRUCT = 'uint:1, uint:7, uintbe:24, uintbe:16'

    @classmethod
    def decode(cls, b):
        ctl, ttl, seq, src = bitstring.BitStream(b).unpack(cls.NETWORK_HEADER_STRUCT)


class NetworkEncryptedData:
    NETWORK_ENCRYPTED_STRUCT = 'uintbe:16, bytes'

    @classmethod
    def decode(cls, b):
        return bitstring.BitStream(b).unpack(cls.NETWORK_ENCRYPTED_STRUCT)

    def to_bytes(self):
        return bitstring.pack(self.NETWORK_ENCRYPTED_STRUCT, self.dst, self.pdu).bytes

class NetworkMessage:
    NETWORK_MESSAGE_STRUCT = 'uint:1, uint:7, bytes'
    def __init__(self, ctl:int, ttl:int, seq:int, src:int, dst:int, pdu:bytes):
        self._ctl = ctl
        self._ttl = ttl
        self._seq = seq
        self._src = src
        self._dst = dst
        self._pdu = pdu

    @property
    def msg_type(self):
        if self._ctl == 1 and self._pdu[0] == 0x00:
            return MessageType.UnSegmentControlMessage
        elif self._ctl == 1:
            return MessageType.SegmentControlMessage
        elif self._pdu[0] & 0x80 == 0x00:
            return MessageType.UnSegmentAccessMessage
        else:
            return MessageType.SegmentAccessMessage

    @classmethod
    def decode(cls, data:bytes):
        return iv_check, nid, header, pdu_mic = bitstring.BitStream(b).unpack(cls.NETWORK_MESSAGE_STRUCT)

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


class UnProvisionedBeacon:
    UNPROVISIONED_BEACON_STRUCT = 'uint:8, bytes:16, uintbe:16, bytes'
    def __init__(self, device_uuid, oob, url_hash=None):
        self._uuid = device_uuid
        self._oob = oob
        self._url_hash = url_hash

    @classmethod
    def from_bytes(cls, b):
        _, bytes_uuid, bytes_oob, bytes_url_hash = bitstring.BitStream(b).unpack(cls.UNPROVISIONED_BEACON_STRUCT)
        _uuid = uuid.UUID(bytes=bytes_uuid)
        _oob = bytes_oob
        _url_hash = bytes_url_hash
        return cls(_uuid, _oob, _url_hash)

class ProvisionedBeacon:
    PROVISIONED_BEACON_STRUCT = 'uint:8, uint:8, bytes:8, uintbe:32, bytes:8'
    def __init__(self, flags, networkid, iv_index, authvalue):
        self._networkid = networkid
        self._iv_index = iv_index
        self._authvalue = authvalue

    @classmethod
    def from_bytes(cls, b):
        _, _flags, _networkid, _iv_index, _authvalue = bitstring.BitStream(b).unpack(cls.PROVISIONED_BEACON_STRUCT)
        return cls(_flags, _networkid, _iv_index, _authvalue)

if __name__ == "__main__":
    from Context import *
    from Util import *

    

    netkeys = [
        NetworkKey.fromString('BFF1AEBF4423B996BE05107444DED115', iv_index=0)
    ]

    appkeys = [
        ApplicationKey.fromString(
            'DCAEDABDAD04F67E690FEB70081A2FF9', iv_index=3903),
        ApplicationKey.fromString(
            'EE3DEBA7D4A9ADE41DF1C2EF0701CBB5', iv_index=3528),
        ApplicationKey.fromString(
            '8962E07FE0498ECBB996E5E88FADD7CD', iv_index=2268),
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

    with MeshContext(netkeys=netkeys, appkeys=appkeys) as context:
        import socket
        x = Decoder('adsf')
        import sys
        sys.exit()

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
                        print(rssi, addr.hex(), msg.header.ttl, msg.header.seq, 'from: %04x' % msg.header.src, 'to: %04x' % msg.pdu.dst, msg.msg_type)
                # elif payload[0] == 0x2b:
                #     provisioned = payload[1][0] == 0x01
                #     if provisioned:
                #         msg = ProvisionedBeacon.from_bytes(payload[1])
                #         print(rssi, addr.hex(), msg._networkid.hex())
                #     else:
                #         msg = UnProvisionedBeacon.from_bytes(payload[1])
                #         print(rssi, addr.hex(), msg._uuid)

