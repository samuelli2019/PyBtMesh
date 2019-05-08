import time
import os
from btmesh.Context import *
from btmesh.Util import *
from btmesh.Message import *

netkeys = [
    NetworkKey.fromString(
        '27D03FD339A0ED2B35159A97DEE5BCA9', iv_index=0, tag='network')
]

appkeys = [
    ApplicationKey.fromString(
        '354242690103C7D7271B8D01AF58297F', iv_index=738, tag='Generic'),
    ApplicationKey.fromString(
        'FCB937EAE46DFF7E04DE63C08746F5CA', iv_index=663, tag='Setup'),
    ApplicationKey.fromString(
        '5ECB8B26A3B24130B4F088DD701FD929', iv_index=3720, tag='Vendor'),
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
        print(s.hex())
        print('i != total_len')
    return packet_list


def bin_to_hex_str(s): return ' '.join(map('{:02x}'.format, s))


output_position = '>/dev/null'
# output_position = ''


def callback(netkey, appkey, src: int, dst: int, opcode: int, parameters: bytes):
    msg = ctx.encode_message(src=src, dst=dst, ttl=63, seq=0xffffff,
                             opcode=opcode, parameters=parameters, app_keyIndex=0)
    print(msg.hex())

    ctx.decode_message(msg)

    os.system('hcitool -i hci0 cmd 0x08 0x000a 00 ' + output_position)
    fixed_header = 'hcitool -i hci0 cmd 0x08 0x0008 '
    pdu_len = len(msg) + 1
    all_pdu_len = pdu_len + 1
    parameter = bytes([all_pdu_len] + [pdu_len] + [0x2a]) + msg
    parameter = parameter.ljust(32, b'\x00')
    cmd1 = fixed_header + bin_to_hex_str(parameter) + output_position
    # cmd2 = 'hciconfig hci0 leadv 3'
    os.system(cmd1)
    os.system(
        'hcitool -i hci0 cmd 0x08 0x0006 a0 00 a0 00 03 00 00 00 00 00 00 00 00 07 00 ' + output_position)
    os.system('hcitool -i hci0 cmd 0x08 0x000a 01 ' + output_position)
    time.sleep(0.3)
    os.system('hcitool -i hci0 cmd 0x08 0x000a 00 ' + output_position)


with MeshContext(netkeys=netkeys, appkeys=appkeys, OnAccessMsg=callable) as ctx:
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('192.168.113.250', 10010))
    f = sock.makefile()
    while True:
        l = f.readline()
        rssi, addr, data = eval(l)
        addr = Addr(addr)
        payloads = None
        try:
            payloads = PayloadDecode(data)
        except IndexError:
            # print(rssi, addr, data.hex())
            continue
        for payload in payloads:
            packet = AdvertisingMessage.from_bytes(payload)
            if isinstance(packet, MeshMessage):
                # print(rssi, addr)
                ctx.decode_message(packet)
            elif isinstance(packet, MeshBeacon):
                pass
