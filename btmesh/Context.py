#!/bin/env python3

import operator
import logging
import bitstring
import cryptography
from btmesh import Util
from btmesh import Message


__all__ = ['CannotInitialError', 'MeshContext']

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
    def __init__(self, context, OnAccessMsgCb=None, OnControlMsgCb=None):
        self._streams = dict()
        self._ctx = context
        def _caller(netkey, appkey, src:int, dst:int, opcode:int, parameters:bytes):
            print("from %04x to %04x opcode: %x" % (src, dst, opcode), 'parameter:', ' '.join(map('{:02x}'.format, parameters)))
        self._on_access_msg = _caller if OnAccessMsgCb is None else OnAccessMsgCb
        def _ctl_caller(netkey, src: int, dst: int, opcode: int, parameters: bytes):
            print("from %04x to %04x control opcode: %x" % (src, dst, opcode), 'parameter:', ' '.join(map('{:02x}'.format, parameters)))
        self._on_control_msg = _ctl_caller if OnControlMsgCb is None else OnControlMsgCb

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
        self._on_access_msg(netkey, appkey, src, dst, opcode, parameters)

    def _contol_caller(self, netkey, src:int, dst:int, opcode:int,parameters:bytes):
        self._on_control_msg(netkey, src, dst, opcode, parameters)

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
        # print('not decrypted')
        return False

    def _decode_devdata(self, msg, data, szmic=False, seqauth=None):
        for devkey in self._ctx.devicekeys:
            if devkey._nodeid == msg._dst or devkey._nodeid == msg._src:
                try:
                    nounce = None
                    if seqauth is not None:
                        nounce = device_nounce(msg._src, msg._dst, seqauth,
                                             msg.netkey.iv_index, szmic)
                    else:
                        nounce = device_nounce(msg._src, msg._dst, msg._seq,
                                             msg.netkey.iv_index, szmic)
                    d = Util.aes_ccm_decrypt(devkey.key, nounce, data)

                    self._access_caller(
                        msg.netkey, devkey, msg._src, msg._dst, d)
                    return True
                except cryptography.exceptions.InvalidTag:
                    # print('decode error')
                    # print(data.hex())
                    return False
        return False

    def do_parse(self, trait):
        msgs = self._streams[trait]

        if isinstance(msgs[0]._UpperMsg, Message.ControlMessage):
            # print(msgs[0]._UpperMsg)
            self._on_control_msg(msgs[0].netkey, msgs[0].src, msgs[0].dst, msgs[0]._UpperMsg)
            self._on_control_msg(msgs[0].netkey, msgs[0]._src, msgs[0]._dst, msgs[0]._UpperMsg._opcode, msgs[0]._UpperMsg._parameters)
        elif isinstance(msgs[0]._UpperMsg, Message.SegmentAccessMessage):
            if len(msgs) >= msgs[0]._UpperMsg._segN:
                slots = list(range(msgs[0]._UpperMsg._segN+1))
                
                seq_list = []
                trait_list = []
                for msg in msgs:
                    seq_list.append(msg._seq - msg._UpperMsg._segO)
                    trait_list.append(msg.trait)
                    slots[msg._UpperMsg._segO] = msg._UpperMsg._pdu
                # check is all data received
                for i in range(len(slots)):
                    if isinstance(slots[i], int):
                        # print('not complement: ', ''.join(map(lambda c:'*' if isinstance(c, int) else '.', slots)))
                        return
                iv_index_0 = msgs[0].netkey.iv_index
                # seq_0 = min(seq_list) & 0x3fff
                # mask = (iv_index_0 << 24)
                # mask &= 0xfc000
                # seqauth = mask | seq_0
                # print(msgs[0]._seq)
                # print(trait_list)
                # print(seq_list, iv_index_0, hex(seqauth))
                data = b''.join(slots)
                # seqauth = seq_0
                seqauth = min(seq_list)
                if msgs[0]._UpperMsg._akf == 1:
                    self._decode_appdata(msgs[0], data, msg._UpperMsg._szmic, seqauth)
                    del self._streams[trait]
                else:
                    self._decode_devdata(msgs[0], data, msg._UpperMsg._szmic, seqauth)
                    del self._streams[trait]

        elif isinstance(msgs[0]._UpperMsg, Message.AccessMessage):
            data = msgs[0]._UpperMsg._pdu
            if msgs[0]._UpperMsg._akf == 1:
                if self._decode_appdata(msgs[0], data):
                    del self._streams[trait]
            else:
                if self._decode_devdata(msgs[0], data):
                    del self._streams[trait]

            
        elif isinstance(msgs[0]._UpperMsg, Message.SegmentControlMessage):
            # print(msgs[0]._UpperMsg)
            self._contol_caller(msgs[0].netkey, msgs[0].src, msgs[0].dst, msgs[0]._UpperMsg._opcode, msgs[0]._UpperMsg._parameters)
        elif isinstance(msgs[0]._UpperMsg, Message.SegmentAckMessage):
            # print(msgs[0]._UpperMsg)
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
                    if devkey._nodeid == msg._dst or devkey._nodeid == msg._src:
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
    def __init__(self, netkeys=[], appkeys=[], devicekeys=[],OnNetworkMsg=None , OnAccessMsg=None, OnControlMsg=None):
        self._netkeys = netkeys
        self._appkeys = appkeys
        self._devicekeys = devicekeys
        self._on_network_msg = OnNetworkMsg
        self._msgmgr = MessageStreamMgr(self, OnAccessMsgCb=OnAccessMsg, OnControlMsgCb=OnControlMsg)

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
        # print(iv_index, key.iv_index)
        # print(nid, key.nid)
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
                if self._on_network_msg is not None:
                    self._on_network_msg(i, msg)
                # print(msg._ctl, msg._ttl, msg._seq, "from: %04x" % msg._src, "to: %04x" % msg._dst, msg._UpperMsg)
                    # print(data.hex())
                key_index = i
                msg.netkey = self._netkeys[i]
                self._msgmgr.append(msg)
                break
        else:
            # print('not network')
            return None
        
        return key_index, msg

    def decode_secure_network_beacon(self, data:bytes):
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

    def decode_unprovisioned_network_beacon(self, data:bytes):
        return Message.UnProvisionedBeacon.from_bytes(data)


    def encode_message(self, src:int, dst:int, ttl:int, seq:int, opcode:int, parameters=b'', network_keyIndex=0, app_keyIndex=0, devkey_index=None):
        import btmesh.MeshOpcode
        if opcode > 65535:
            l = 3
        elif opcode > 255:
            l = 2
        else:
            l = 1
        pdu = opcode.to_bytes(l, 'big') + parameters
        l = len(pdu)
        if btmesh.MeshOpcode.opcode_is_ctl(opcode):
            return None
        else:
            if l > 100:
                return None
                # upper_msg = Message.SegmentAccessMessage(1, self.appkeys[app_keyIndex.aid], 1, seq)
            else:
                if devkey_index is None:
                    upper_msg = Message.AccessMessage(1, self.appkeys[app_keyIndex].aid, pdu)
                else:
                    upper_msg = Message.AccessMessage(0, 0, pdu)
        
        netmsg = Message.NetworkMessage(0, ttl, seq, src, dst, upper_msg)
        nounce = application(src, dst, seq, self.netkeys[network_keyIndex].iv_index)

        if devkey_index is None:
            netmsg._UpperMsg._pdu = dst.to_bytes(2, 'big') + upper_msg.to_bytes()[:1] + Util.aes_ccm(self.appkeys[app_keyIndex].key, nounce, pdu)
        else:
            nounce = device_nounce(src, dst, seq, self.netkeys[network_keyIndex].iv_index)
            netmsg._UpperMsg._pdu = dst.to_bytes(2, 'big') + upper_msg.to_bytes()[:1] + Util.aes_ccm(self.devkeys[devkey_index].key, nounce, pdu)


        net_nounce = network_nounce(0, ttl, src, seq, self.netkeys[network_keyIndex].iv_index)
        net_pdu = Util.aes_ccm(self.netkeys[network_keyIndex].encrypt_key, net_nounce, netmsg._UpperMsg._pdu)

        _header = Message.NetworkHeader.encode(0, ttl, seq, src)
        
        header = header_obfs(_header, self.netkeys[network_keyIndex], net_pdu)

        return bitstring.pack('uint:1, uint:7, bytes, bytes',
                            self.netkeys[network_keyIndex].iv_index & 1, self.netkeys[network_keyIndex].nid,
                            header, net_pdu).bytes
        

    def encode_secure_network_beacon(self, network_keyIndex):
        pass

if __name__ == "__main__":
    with MeshContext():
        pass
