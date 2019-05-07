#!/bin/env python3

import operator
import uuid
from functools import lru_cache
import bitstring


__all__ = ['AdvertisingMessage', 'MeshPBADV', 'MeshMessage', 'MeshBeacon', 'MessageType',
            'ControlMessage', 'SegmentAckMessage', 'SegmentControlMessage',
            'AccessMessage', 'SegmentAccessMessage', 'get_msg',
            'NetworkHeader', 'NetworkEncryptedData', 'NetworkMessage',
            'UnProvisionedBeacon', 'ProvisionedBeacon']

class AdvertisingMessage:
    MESSAGE_STRUCT = 'uint:8, bytes'
    MESH_PBADV = 0x29
    MESH_MESSAGE = 0x2a
    MESH_BEACON = 0x2b

    @classmethod
    def from_bytes(cls, data:bytes):
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
    SegmentAckMessage = 'SegmengAckMessage'
    SegmentControlMessage = 'SegmentControlMessage'
    UnSegmentAccessMessage = 'UnSegmentAccessMessage'
    SegmentAccessMessage = 'SegmentAccessMessage'


class BaseMessage:
    STRUCT = 'bytes'

    def pack(self):
        return bitstring.pack(self.STRUCT, *self._elements)

    @classmethod
    def unpack(cls, data:bytes):
        return bitstring.ConstBitStream(data).unpack(cls.STRUCT)

    @property
    def trait(self):
        # string to inditity different stream
        return str(self)

    @classmethod
    def from_bytes(cls, data:bytes):
        return cls(*(cls.unpack(data)))

    def to_bytes(self):
        return self.pack().bytes


class ControlMessage(BaseMessage):
    STUCT = 'pad:0, uint:7, bytes'
    def __init__(self, opcode:int, parameters:bytes):
        self._opcode = opcode
        self._parameters = parameters
        self._trait = opcode
        self._elements = (self._opcode, self._parameters)

    @property
    def MsgType(self):
        return MessageType.UnSegmentControlMessage

    def __str__(self):
        return "Control Message: %d" % self._opcode


class SegmentAckMessage(BaseMessage):
    STRUCT = 'pad:8, uint:1, uint:13, uint:2, uintbe:32'
    def __init__(self, obo:int, seqzero:int, rfu:int, blockack:int):
        self._obo = obo
        self._seqzero = seqzero
        self._rfu = rfu
        # this is a bitmap
        self._blockack = blockack
        self._elements = (obo, seqzero, rfu, blockack)

    @property
    def MsgType(self):
        return MessageType.SegmentAckMessage

    def __str__(self):
        return "Message Segment ACK: %s" % bin(self._blockack)[2:].rjust(5, '0')


class SegmentControlMessage(BaseMessage):
    STRUCT = 'uint:1, uint:7, uint:1, uint:13, uint:5, uint:5, uintbe:32'
    def __init__(self, seg:int, opcode:int, rfu:int, seqzero:int, segO:int, segN:int, data:bytes):
        self._seg = seg
        self._opcode = opcode
        self._rfu = rfu
        self._seqzero = seqzero
        self._segO = segO
        self._segN = segN
        self._data = data
        self._elements = (seg, opcode, rfu, seqzero, segO, segN, data)

    @property
    def MsgType(self):
        return MessageType.SegmentControlMessage

    def __str__(self):
        return "Control Message Segment: %02x %d of %d" % (self._opcode, self._segO, self._segN)

    @property
    @lru_cache(maxsize=1)
    def trait(self):
        return "%x %d %x" % (self._opcode, self._segN, self._seqzero)


class AccessMessage(BaseMessage):
    STRUCT = 'pad:1, uint:1, uint:6, bytes'
    def __init__(self, akf:int, aid:int, pdu:bytes):
        self._akf = akf
        self._aid = aid
        self._pdu = pdu
        self._elements = (akf, aid, pdu)

    @property
    def MsgType(self):
        return MessageType.UnSegmentAccessMessage

    def __str__(self):
        return "Access Message AID: %02x" % (self._aid)


class SegmentAccessMessage(BaseMessage):
    STRUCT = 'pad:1, uint:1, uint:6, uint:1, uint:13, uint:5, uint:5, bytes'
    def __init__(self, akf:int, aid:int, szmic:int, seqzero:int, segO:int, segN:int, pdu:bytes):
        self._akf = akf
        self._aid = aid
        self._szmic = szmic
        self._seqzero = seqzero
        self._segO = segO
        self._segN = segN
        self._pdu = pdu
        self._elements = (akf, aid, szmic, seqzero, segO, segN, pdu)

    @property
    def MsgType(self):
        return MessageType.SegmentAccessMessage

    @property
    @lru_cache(maxsize=1)
    def trait(self):
        return "%d %d %x %d" % (self._akf, self._aid, self._seqzero, self._segN)

    def __str__(self):
        return "Segment Message: %d of %d" % (self._segO, self._segN)

def get_msg(ctl, data:bytes):
    isSeg,_ = bitstring.ConstBitStream(data).unpack('uint:1, bits')
    if ctl == 1 and isSeg == 0:
        if data[0] == 0x00:
            return SegmentAckMessage.from_bytes(data)
        else:
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

    @property
    def netkey(self):
        return self._netkey
    
    @netkey.setter
    def netkey(self, key):
        self._netkey = key

    @property
    def trait(self):
        return '%04x %04x %s' % (self._src, self._dst, self._UpperMsg.trait)

    @classmethod
    def decode(cls, data:bytes):
        return bitstring.BitStream(data).unpack(cls.NETWORK_MESSAGE_STRUCT)


class UnProvisionedBeacon:
    UNPROVISIONED_BEACON_STRUCT = 'uint:8, bytes:16, uintbe:16, bytes'
    def __init__(self, device_uuid, oob, url_hash=None):
        self._uuid = device_uuid
        self._oob = oob
        self._url_hash = url_hash

    @property
    def uuid(self):
        return self._uuid

    @property
    def OOB(self):
        return self._oob

    @property
    def URI_Hash(self):
        return self._url_hash

    def __str__(self):
        return 'UUID: {}'.format(self._uuid)

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
        self._flags = flags
        self._networkid = networkid
        self._iv_index = iv_index
        self._authvalue = authvalue

    @property
    def flags(self):
        return self._flags

    @property
    def NetworkId(self):
        return self._networkid

    @property
    def IV_Index(self):
        return self._iv_index

    @property
    def AuthValue(self):
        return self._authvalue

    def __str__(self):
        return 'Network Id: {}'.format(self._networkid.hex())

    @classmethod
    def from_bytes(cls, b):
        _, _flags, _networkid, _iv_index, _authvalue = bitstring.BitStream(b).unpack(cls.PROVISIONED_BEACON_STRUCT)
        return cls(_flags, _networkid, _iv_index, _authvalue)

if __name__ == "__main__":
    pass

