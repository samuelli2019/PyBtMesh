from btmesh.Context import *
from btmesh.Util import *
from btmesh.Message import *

netkeys = [
    NetworkKey.fromString(
        '395CF5599D988B6AECEF924D6F840724', iv_index=0, tag='network')
]

appkeys = [
    ApplicationKey.fromString(
        '297537E2121446E9DEBCD30F2C843766', iv_index=953, tag='application 1'),
    ApplicationKey.fromString(
        'E02CBF7DC54AE7B13A79FEA9FE06CD27', iv_index=865, tag='application 2'),
    ApplicationKey.fromString(
        '7B05098D194F76F70C490638CD3D9EAD', iv_index=17, tag='application 3'),
]

devkeys = [
    DeviceKey.fromString(
        '1FFCC17C6411835164769DF36BF8AE01', nodeid=2),
    DeviceKey.fromString(
        '5ABD9DC7F2C43CBE335D47501E04A23F', nodeid=4),
    DeviceKey.fromString(
        'DDD0035D1D3AC520E8031700C812BC82', nodeid=6),
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


with MeshContext(netkeys=netkeys, appkeys=appkeys, devicekeys=devkeys) as ctx:
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('192.168.113.250', 10010))
    f = sock.makefile()
    while True:
        l = f.readline()
        rssi, addr, data = eval(l)
        addr = Util.Addr(addr)
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
