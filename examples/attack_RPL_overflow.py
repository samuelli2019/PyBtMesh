import os
import time
from btmesh.Context import MeshContext
from btmesh.Util import NetworkKey, ApplicationKey

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

# like: 11 22 33 44


def bin_to_hex_str(s): return ' '.join(map('{:02x}'.format, s))


output_position = '>/dev/null'
# output_position = ''


def send(data: bytes):
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


with MeshContext(netkeys=netkeys, appkeys=appkeys) as ctx:
    for i in range(0x1000, 0x1100):
        print('\r%d' % i, end='')
        msg = ctx.encode_message(src=i, dst=0xc000, ttl=63, seq=1,
                                 opcode=0x00, app_keyIndex=0)
        send(msg)
    print()
