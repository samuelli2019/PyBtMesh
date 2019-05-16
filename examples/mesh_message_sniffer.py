from btmesh.Context import *
from btmesh.Util import *
from btmesh.Message import *

netkeys = [
    NetworkKey.fromString(
        '27D03FD339A0ED2B35159A97DEE5BCA9', iv_index=0, tag='network'),
    NetworkKey.fromString(
        '59C8EAF37DE9736577EE37CEBAF69834', iv_index=1, tag='network')
]

appkeys = [
    ApplicationKey.fromString(
        '354242690103C7D7271B8D01AF58297F', iv_index=738, tag='Generic'),
    ApplicationKey.fromString(
        '8D81A65547D0DEA220DCFFE50DCF4466', iv_index=738, tag='Generic'),

    ApplicationKey.fromString(
        'FCB937EAE46DFF7E04DE63C08746F5CA', iv_index=663, tag='Setup'),
    ApplicationKey.fromString(
        '972E5A1418CD798FBBB05D75A7F5A934', iv_index=663, tag='Setup'),

    ApplicationKey.fromString(
        '5ECB8B26A3B24130B4F088DD701FD929', iv_index=3720, tag='Vendor'),
    ApplicationKey.fromString(
        '76508ABD20686040455F26522E6AB9C5', iv_index=3720, tag='Vendor'),
]


devkeys = [
    DeviceKey.fromString(
        '56C30DC3C38BC8A1EE8828347EF2BCDC', nodeid=1),
    DeviceKey.fromString(
        '114B92083323A0A42AA10D8A22819FE5', nodeid=2),
    DeviceKey.fromString(
        '13A9B57C73EE93432DAF2F692347C71C', nodeid=3),
    DeviceKey.fromString(
        'BAF2A84A6275AC19D82BE5E462A0F5DE', nodeid=5),
    DeviceKey.fromString(
        '964F9E6F70131B7C79C2DA6F3BAE33DC', nodeid=7),
    DeviceKey.fromString(
        'C7DAAE12E656F77888709DF7219DE080', nodeid=9),
    DeviceKey.fromString(
        '4F516CF5296EA01A6CD418B799EC8B43', nodeid=0x0b),
    DeviceKey.fromString(
        'B4D2C6369E73B2A1F55A1584E385B770', nodeid=0x0d),
    DeviceKey.fromString(
        '8CD19C36DEB06BA29E36DFB98E6F5341', nodeid=0x0f),
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


def on_net_msg(i, msg):
    print("from %04x to %04x" % (msg._src, msg._dst), msg._UpperMsg)


with MeshContext(netkeys=netkeys, appkeys=appkeys, devicekeys=devkeys, OnNetworkMsg=on_net_msg) as ctx:
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
