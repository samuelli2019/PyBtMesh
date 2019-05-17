from bluepy import btle

from btmesh import Context
from btmesh import Util
from btmesh import Message
from btmesh import MeshOpcode

netkeys = [
    Util.NetworkKey.fromString(
        '27D03FD339A0ED2B35159A97DEE5BCA9', iv_index=0, tag='network'),
    Util.NetworkKey.fromString(
        '59C8EAF37DE9736577EE37CEBAF69834', iv_index=1, tag='network')
]

appkeys = [
    Util.ApplicationKey.fromString(
        '354242690103C7D7271B8D01AF58297F', iv_index=738, tag='Generic'),
    Util.ApplicationKey.fromString(
        '8D81A65547D0DEA220DCFFE50DCF4466', iv_index=738, tag='Generic'),

    Util.ApplicationKey.fromString(
        'FCB937EAE46DFF7E04DE63C08746F5CA', iv_index=663, tag='Setup'),
    Util.ApplicationKey.fromString(
        '972E5A1418CD798FBBB05D75A7F5A934', iv_index=663, tag='Setup'),

    Util.ApplicationKey.fromString(
        '5ECB8B26A3B24130B4F088DD701FD929', iv_index=3720, tag='Vendor'),
    Util.ApplicationKey.fromString(
        '76508ABD20686040455F26522E6AB9C5', iv_index=3720, tag='Vendor'),
]


devkeys = [
]


class ScanDelegate(btle.DefaultDelegate):
    def __init__(self, ctx):
        btle.DefaultDelegate.__init__(self)
        self._ctx = ctx

    def handleDiscovery(self, dev, isNewDev, isNewData):
        if isNewData:
            temp = dev.getValueText(0x2a)
            if temp is not None:
                self._ctx.decode_message(bytes.fromhex(temp))


def bin_to_hex_str(s): return ' '.join(map('{:02x}'.format, s))


output_position = '>/dev/null'
# output_position = ''


def send(msg: bytes):
    import os
    import time
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


def callback(netkey, appkey, src: int, dst: int, opcode: int, parameters: bytes):
    print("\t%04x -> %04x op: %s data: %s" %
          (src, dst, MeshOpcode.opcode_description(opcode), ' '.join(map('{:02x}'.format, parameters))))


ctx = Context.MeshContext(
    netkeys=netkeys, appkeys=appkeys, OnAccessMsg=callback)

msg = ctx.encode_message(0x101, 0xc000, 1, 402, 0x8205, 1, 1)

scanner = btle.Scanner().withDelegate(ScanDelegate(ctx))
while True:
    scanner.scan(10.0, passive=True)
