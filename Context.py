#!/bin/env python3

import operator
import logging
import bitstring
import cryptography
import Util
import Message


mesh_context = None


class ContextConflictsError(Exception):
    pass

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

class MessageStream:
    def __init__(self):
        pass

class MessageStreamMgr:
    def __init__(self):
        pass

class MeshContext:
    def __init__(self, netkeys=[], appkeys=[], devicekeys=[]):
        self._netkeys = netkeys
        self._appkeys = appkeys
        self._devicekeys = devicekeys

    @property
    def netkeys(self):
        return self._netkeys

    @property
    def appkeys(self):
        return self._appkeys

    def __enter__(self):
        global mesh_context
        if mesh_context is not None:
            raise ContextConflictsError()
        if len(self._netkeys) == 0:
            logging.warning('Enter Mesh Context with 0 netkeys')
        if len(self._appkeys) == 0:
            logging.warning('Enter Mesh Context with 0 appkeys')
        logging.debug('Enter Mesh Context')
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        global mesh_context
        mesh_context = None
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

        return Message.NetworkMessage(ctl, ttl, seq, src, dst, msg)

    def _decode_app_msg(self, data:bytes, appkey_index:int):
        pass

    def decode_message(self, data: bytes, netkey_index: int = None, appkey_index: int = None):
        key_index, msg = None, None
        for i in range(len(self._netkeys)):
            msg = self._decode_net_msg(data, i)
            if msg is not None:
                print(msg._ctl, msg._ttl, msg._seq, "from: %04x" % msg._src, "to: %04x" % msg._dst, msg._UpperMsg.MsgType)
                key_index = i
                break
        else:
            return None
        
        return key_index, msg

    def decode_secure_network_beacon(self, data):
        pass

    def encode_message(self, msg, network_keyIndex=0, app_keyIndex=0):
        pass

    def encode_secure_network_beacon(self, network_keyIndex):
        pass

if __name__ == "__main__":
    with MeshContext():
        pass
