from bluepy import btle

from btmesh import Context
from btmesh import Util
from btmesh import Message
from btmesh import MeshOpcode

netkeys = [
    Util.NetworkKey.fromString(
        '27D03FD339A0ED2B35159A97DEE5BCA9', iv_index=0, tag='network')
]

appkeys = [
    Util.ApplicationKey.fromString(
        '354242690103C7D7271B8D01AF58297F', iv_index=738, tag='Generic'),
    Util.ApplicationKey.fromString(
        'FCB937EAE46DFF7E04DE63C08746F5CA', iv_index=663, tag='Setup'),
    Util.ApplicationKey.fromString(
        '5ECB8B26A3B24130B4F088DD701FD929', iv_index=3720, tag='Vendor'),
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


def callback(netkey, appkey, src: int, dst: int, opcode: int, parameters: bytes):
    print("%04x -> %04x op: %s" %
          (src, dst, MeshOpcode.opcode_description(opcode)))


ctx = Context.MeshContext(
    netkeys=netkeys, appkeys=appkeys, OnAccessMsg=callback)

scanner = btle.Scanner().withDelegate(ScanDelegate(ctx))
while True:
    scanner.scan(10.0, passive=True)
