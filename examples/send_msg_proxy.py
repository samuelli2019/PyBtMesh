from btmesh.Context import MeshContext
from btmesh.Util import NetworkKey, ApplicationKey

netkeys = [
    NetworkKey.fromString(
        'EA82FE14E46D3CDE45A615AD24AFB66E', iv_index=0, tag='network')
]

appkeys = [
    ApplicationKey.fromString(
        '06645D42963E74ECEB5A75CC27FD2C12', iv_index=3300, tag='Generic'),
    ApplicationKey.fromString(
        '7F2A2663976242DC0857892C07409B0D', iv_index=136, tag='Setup'),
    ApplicationKey.fromString(
        'A4F84F3A36C326211D9CEE44991A5618', iv_index=3704, tag='Vendor'),
]

with MeshContext(netkeys=netkeys, appkeys=appkeys) as ctx:
    msg = ctx.encode_message(src=1, dst=2, ttl=5, seq=100,
                             opcode=0x8203, parameters=b'\x00\x00\x00\x00')
    print(msg.hex())
    import bluepy
    dev = bluepy.Peripheral('f2:d5:f3:7d:76:e7', addrType=ADDR_TYPE_RANDOM)
    service = dev.getServiceByUUID(0x1828)
    character = service.getCharacteristics(0x2add)[0]
    character.write(msg)
