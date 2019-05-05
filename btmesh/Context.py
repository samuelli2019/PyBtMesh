#!/bin/env python3

import operator
import logging
import bitstring
import cryptography
from btmesh import Util
from btmesh import Message


class CannotInitialError(Exception):
    pass

def header_obfs(header: bytes, key: Util.NetworkKey, pdu: bytes):
    privacy_random = bitstring.pack(
        'pad:40, uintbe:32, bytes:7', key.iv_index, pdu[:7]).bytes
    pecb = Util.aes_ecb(key.privacy_key, privacy_random)[:6]
    return bytes(map(operator.xor, header, pecb))

def network_nounce(ctl, ttl, src, seq, iv_index):
    return bitstring.pack('uint:8, uint:1, uint:7, uintbe:24, uintbe:16, pad:16, uintbe:32',
                          0x00, ctl, ttl, seq, src, iv_index).bytes


def application(src, dst, seq, iv_index, szmic=False):
    return bitstring.pack('uint:8, uint:1, pad:7, uintbe:24, uintbe:16, uintbe:16, uintbe:32',
                              0x01, szmic, seq, src, dst, iv_index).bytes


def device_nounce(src, dst, seq, iv_index, szmic=False):
    return bitstring.pack('uint:8, uint:1, pad:7, uintbe:24, uintbe:16, uintbe:16, uintbe:32',
                              0x02, szmic, seq, src, dst, iv_index).bytes

class MessageStream:
    def __init__(self):
        pass

class MessageStreamMgr:
    def __init__(self, context, OnMessageCb=None):
        self._streams = dict()
        self._ctx = context
        def _caller(netkey, appkey, src:int, dst:int, opcode:int, parameters:bytes):
            print("from: %04x to: %04x opcode: %x" % (src, dst, opcode), 'parameter:', ' '.join(map('{:02x}'.format, parameters)))
        self._on_msg = _caller if OnMessageCb is None else OnMessageCb

    def _access_caller(self, netkey, appkey, src: int, dst: int, payload: bytes):
        t = payload[0]
        opcode = None
        parameters = None
        if t & 0x80 == 0x00:
            opcode = payload[0]
            parameters = payload[1:]
        elif t & 0xc0 == 0x80:
            opcode = int.from_bytes(payload[:2], 'big')
            parameters = payload[2:]
        elif t & 0xc0 == 0xc0:
            opcode = int.from_bytes(payload[:3], 'big')
            parameters = payload[3:]
        self._on_msg(netkey, appkey, src, dst, opcode, parameters)

    def _contol_caller(self):
        pass

    def _ack_caller(self):
        pass

    def _decode_appdata(self, msg, data, szmic=False, seqauth=None):
        for appkey in self._ctx.appkeys:
            if appkey.aid & 0x3f == msg._UpperMsg._aid:
                try:
                    nounce = None
                    if seqauth is not None:
                        nounce = application(msg._src, msg._dst, seqauth,
                                         msg.netkey.iv_index, szmic)
                    else:
                        nounce = application(msg._src, msg._dst, msg._seq,
                                         msg.netkey.iv_index, szmic)
                    d = Util.aes_ccm_decrypt(appkey.key, nounce, data)

                    self._access_caller(
                        msg.netkey, appkey, msg._src, msg._dst, d)
                    return True
                except cryptography.exceptions.InvalidTag:
                    pass
        return False

    def _decode_devdata(self, msg, data, szmic=False, seqauth=None):
        for devkey in self._ctx.devicekeys:
            if devkey._nodeid == msg._dst:
                try:
                    nounce = None
                    if seqauth is not None:
                        nounce = application(msg._src, msg._dst, seqauth,
                                             msg.netkey.iv_index, szmic)
                    else:
                        nounce = application(msg._src, msg._dst, msg._seq,
                                             msg.netkey.iv_index, szmic)
                    d = Util.aes_ccm_decrypt(devkey.key, nounce, data)

                    self._access_caller(
                        msg.netkey, devkey, msg._src, msg._dst, d)
                    return True
                except cryptography.exceptions.InvalidTag:
                    # print('key error')
                    pass
        return False

    def do_parse(self, trait):
        msgs = self._streams[trait]

        if isinstance(msgs[0]._UpperMsg, Message.ControlMessage):
            print(msgs[0]._UpperMsg)
            self._on_msg(msgs[0]._UpperMsg)
        elif isinstance(msgs[0]._UpperMsg, Message.SegmentAccessMessage):
            if len(msgs) >= msgs[0]._UpperMsg._segN:
                slots = list(range(msgs[0]._UpperMsg._segN+1))
                
                seq_list = []
                for msg in msgs:
                    seq_list.append(msg._seq - msg._UpperMsg._segO)
                    slots[msg._UpperMsg._segO] = msg._UpperMsg._pdu
                # check is all data received
                for i in range(len(slots)):
                    if isinstance(slots[i], int):
                        print('not complement: ', ''.join(map(lambda c:'*' if isinstance(c, int) else '.', slots)))
                        return
                iv_index_0 = msgs[0].netkey.iv_index
                seq_0 = msgs[0]._UpperMsg._segO
                mask = seqauth = (iv_index_0 << 24) | seq_0
                mask &= 0xffc00
                seqauth = mask | msgs[0]._UpperMsg._seqzero
                
                seq_0 = min(seq_list)
                data = b''.join(slots)
                seqauth = seq_0
                if msgs[0]._UpperMsg._akf == 1:
                    if self._decode_appdata(msgs[0], data, msg._UpperMsg._szmic, seqauth):
                        del self._streams[trait]
                else:
                    if self._decode_devdata(msgs[0], data, True, seqauth):
                        del self._streams[trait]

        elif isinstance(msgs[0]._UpperMsg, Message.AccessMessage):
            data = msgs[0]._UpperMsg._pdu
            if msgs[0]._UpperMsg._akf == 1:
                if self._decode_appdata(msgs[0], data):
                    del self._streams[trait]
            else:
                if self._decode_devdata(msgs[0], data):
                    del self._streams[trait]

            
        elif isinstance(msgs[0]._UpperMsg, Message.SegmentAccessMessage):
            print(msgs[0]._UpperMsg)
            self._contol_caller()
        elif isinstance(msgs[0]._UpperMsg, Message.SegmentAckMessage):
            print(msgs[0]._UpperMsg)
            self._ack_caller()

    def get_app_key(self, msg: Message.NetworkMessage):
        for appkey in self._ctx.appkeys:
            if appkey.aid & 0x3f == msg._UpperMsg._aid:
                return appkey
        return None

    def check_key(self, msg: Message.NetworkMessage):
        if isinstance(msg._UpperMsg, Message.ControlMessage) or isinstance(msg._UpperMsg, Message.SegmentControlMessage) or isinstance(msg._UpperMsg, Message.SegmentAckMessage):
            return True
        if isinstance(msg._UpperMsg, Message.AccessMessage) or isinstance(msg._UpperMsg, Message.SegmentAccessMessage):
            if msg._UpperMsg._akf == 1:
                if self.get_app_key(msg) is not None:
                    return True
            else:
                for devkey in self._ctx.devicekeys:
                    if devkey._nodeid == msg._dst:
                        return True
        return False


    def append(self, msg: Message.NetworkMessage):
        if not self.check_key(msg):
            return
        if msg.trait in self._streams:
            self._streams[msg.trait].append(msg)
        else:
            self._streams[msg.trait] = [msg]

        self.do_parse(msg.trait)
        

class MeshContext:
    def __init__(self, netkeys=[], appkeys=[], devicekeys=[], OnAccessMsg=None):
        self._netkeys = netkeys
        self._appkeys = appkeys
        self._devicekeys = devicekeys
        self._msgmgr = MessageStreamMgr(self, OnMessageCb=OnAccessMsg)

    @property
    def netkeys(self):
        return self._netkeys

    @property
    def appkeys(self):
        return self._appkeys

    @property
    def devicekeys(self):
        return self._devicekeys

    def __enter__(self):
        if len(self._netkeys) == 0:
            logging.warning('Enter Mesh Context with 0 netkeys')
        if len(self._appkeys) == 0:
            logging.warning('Enter Mesh Context with 0 appkeys')
        logging.debug('Enter Mesh Context')
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        logging.debug('Exit Mesh Context')

    def _decode_net_msg(self, data:bytes, netkey_index:int):
        key = self._netkeys[netkey_index]

        iv_index, nid, payload = Message.NetworkMessage.decode(data)

        #fast check
        if iv_index != (key.iv_index & 0x01) or nid != key.nid & 0x7f:
            return None

        _header, _pdu = bitstring.BitStream(payload).unpack('bytes:6, bytes')

        # decode basic information
        ctl, ttl, seq, src = Message.NetworkHeader.decode(
            header_obfs(_header, key, _pdu))
        
        # decode more information
        tag_len = 8 if ctl == 1 else 4
        nounce = network_nounce(ctl, ttl, src, seq, key.iv_index)
        try:
            temp = Util.aes_ccm_decrypt(
                key.encrypt_key, nounce, _pdu, tag_length=tag_len)
        except cryptography.exceptions.InvalidTag:
            return None
        dst, pdu = Message.NetworkEncryptedData.decode(temp)

        # decode upper message
        msg = Message.get_msg(ctl, pdu)

        netmsg = Message.NetworkMessage(ctl, ttl, seq, src, dst, msg)

        return netmsg

    def decode_message(self, data: bytes, netkey_index: int = None, appkey_index: int = None):
        key_index, msg = None, None
        for i in range(len(self._netkeys)):
            msg = self._decode_net_msg(data, i)
            if msg is not None:
                # print(msg._ctl, msg._ttl, msg._seq, "from: %04x" % msg._src, "to: %04x" % msg._dst, msg._UpperMsg)
                key_index = i
                msg.netkey = self._netkeys[i]
                self._msgmgr.append(msg)
                break
        else:
            return None
        
        return key_index, msg

    def decode_secure_network_beacon(self, data):
        beacon = Message.ProvisionedBeacon.from_bytes(data)
        def get_auth(flags: int, networkid: bytes, ivindex: int, key: Util.NetworkKey):
            temp = bitstring.pack('uint:8, bytes:8, uintbe:32',
                flags, networkid, ivindex)[:8]
            return Util.aes_cmac(key.beacon, temp)
        for i, key in enumerate(self._netkeys):
            auth_value = get_auth(beacon.flags, beacon.NetworkId, beacon.IV_Index, key)
            if auth_value == beacon.AuthValue:
                return i, beacon
        else:
            return -1, beacon

    def decode_unprovisioned_network_beacon(self, data):
        return Message.UnProvisionedBeacon.from_bytes(data)


    def encode_message(self, msg, network_keyIndex=0, app_keyIndex=0):
        pass

    def encode_secure_network_beacon(self, network_keyIndex):
        pass

if __name__ == "__main__":
    with MeshContext():
        pass
