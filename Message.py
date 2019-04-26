#!/bin/env python3

import operator
import uuid
import bitstring
from Util import *

class AdvertisingMessage:
    MESSAGE_STRUCT = 'uint:8, bytes'
    MESH_PBADV = 0x29
    MESH_MESSAGE = 0x2a
    MESH_BEACON = 0x2b

    @classmethod
    def from_bytes(cls, data):
        msg_type, pdu = data
        # msg_type, pdu = bitstring.BitStream(data).unpack(cls.MESSAGE_STRUCT)
        if msg_type == cls.MESH_PBADV:
            return MeshPBADV(pdu)
        elif msg_type == cls.MESH_MESSAGE:
            return MeshMessage(pdu)
        elif msg_type == cls.MESH_BEACON:
            return MeshBeacon(pdu)
        else:
            return None

class MeshPBADV(bytes):
    pass

class MeshMessage(bytes):
    pass

class MeshBeacon(bytes):
    pass

class MessageType:
    UnSegmentControlMessage = 'UnSegmentControlMessage'
    SegmentControlMessage = 'SegmentControlMessage'
    UnSegmentAccessMessage = 'UnSegmentAccessMessage'
    SegmentAccessMessage = 'SegmentAccessMessage'

class ControlMessage:
    STUCT = 'pad:0, uint:7, bytes'
    def __init__(self, opcode, parameters):
        self._opcode = opcode
        self._parameters = parameters

    @property
    def MsgType(self):
        return MessageType.UnSegmentControlMessage

    @classmethod
    def from_bytes(cls, data):
        _, opcode, parameters = bitstring.BitStream(data).unpack(data)
        return cls(opcode, parameters)

class SegmentControlMessage:
    def __init__(self):
        pass

    @property
    def MsgType(self):
        return MessageType.SegmentControlMessage

    @classmethod
    def from_bytes(cls, data):
        pass

class AccessMessage:
    MESSAGE_STRUCT = 'pad:1, uint:1, uint:6, bytes'
    def __init__(self, akf, aid, pdu):
        self._akf = akf
        self._aid = aid
        self._pdu = pdu

    @property
    def MsgType(self):
        return MessageType.UnSegmentAccessMessage

    @classmethod
    def from_bytes(cls, data):
        akf, aid, pdu = bitstring.BitStream(data).unpack(cls.MESSAGE_STRUCT)
        return cls(akf, aid, pdu)

class SegmentAccessMessage:
    def __init__(self):
        pass

    @property
    def MsgType(self):
        return MessageType.SegmentAccessMessage

    @classmethod
    def from_bytes(cls, data):
        pass

def get_msg(ctl, data):
    isSeg,_ = bitstring.ConstBitStream(data).unpack('uint:1, bits')
    if ctl == 1 and isSeg == 0:
        return ControlMessage.from_bytes(data)
    elif ctl == 1:
        return SegmentControlMessage.from_bytes(data)
    elif isSeg == 0:
        return AccessMessage.from_bytes(data)
    else:
        return SegmentAccessMessage.from_bytes(data)

class NetworkHeader:
    NETWORK_HEADER_STRUCT = 'uint:1, uint:7, uintbe:24, uintbe:16'

    @classmethod
    def decode(cls, b):
        return bitstring.BitStream(b).unpack(cls.NETWORK_HEADER_STRUCT)

class NetworkEncryptedData:
    NETWORK_ENCRYPTED_STRUCT = 'uintbe:16, bytes'

    @classmethod
    def decode(cls, b):
        return bitstring.BitStream(b).unpack(cls.NETWORK_ENCRYPTED_STRUCT)

class NetworkMessage:
    NETWORK_MESSAGE_STRUCT = 'uint:1, uint:7, bytes'
    def __init__(self, ctl:int, ttl:int, seq:int, src:int, dst:int, upperMsg):
        self._ctl = ctl
        self._ttl = ttl
        self._seq = seq
        self._src = src
        self._dst = dst
        self._UpperMsg = upperMsg

    @classmethod
    def decode(cls, data:bytes):
        return bitstring.BitStream(data).unpack(cls.NETWORK_MESSAGE_STRUCT)


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
        NetworkKey.fromString('A622C6F2ED28997EE03BC73EF1A01D84', iv_index=0)
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

    with MeshContext(netkeys=netkeys, appkeys=appkeys) as ctx:
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('192.168.113.250', 10010))
        f = sock.makefile()
        while True:
            l = f.readline()
            rssi, addr, data = eval(l)
            addr = Util.Addr(addr)
            payloads = PayloadDecode(data)
            for payload in payloads:
                packet = AdvertisingMessage.from_bytes(payload)
                if isinstance(packet, MeshMessage):
                    print(rssi, addr)
                    ctx.decode_message(packet)
                elif isinstance(packet, MeshBeacon):
                    pass
                # elif payload[0] == 0x2b:
                #     provisioned = payload[1][0] == 0x01
                #     if provisioned:
                #         msg = ProvisionedBeacon.from_bytes(payload[1])
                #         print(rssi, addr.hex(), msg._networkid.hex())
                #     else:
                #         msg = UnProvisionedBeacon.from_bytes(payload[1])
                #         print(rssi, addr.hex(), msg._uuid)

