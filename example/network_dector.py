from btmesh.Context import *
from btmesh.Util import *
from btmesh.Message import *

netkeys = [
    NetworkKey.fromString(
        'AB4007AC44488213239CAA96C968A8C5', iv_index=0, tag='network')
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


with MeshContext(netkeys=netkeys) as ctx:
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
            if isinstance(packet, MeshBeacon):
                print(packet.hex())
