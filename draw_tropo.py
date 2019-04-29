from Context import *
from Message import *
from Util import *

netkeys = [
     NetworkKey.fromString(
          'F31F668126C6BCFF9FC9E068B492F0BD', iv_index=0, tag='network')
     ]

appkeys = [
    ApplicationKey.fromString(
        '1D434F61BDEE7E11BA2ADD9D78A29098', iv_index=3468, tag='application 1'),
    ApplicationKey.fromString(
        '11BECECEBD6E979ED64C30C609BDE34C', iv_index=2824, tag='application 2'),
    ApplicationKey.fromString(
        '4509FAC31BB4EDF851669AE2FEA2F3BC', iv_index=3852, tag='application 3'),
    ]

devkeys = [
    DeviceKey.fromString(
        'DF590A424511618A3293CA1B5348829E', nodeid=2),
    DeviceKey.fromString(
        '9EC0DEF4F64197E2A1F5C3468035CE88', nodeid=4),
    DeviceKey.fromString(
        'FF420B486C309BD9CB60B78376BAADF3', nodeid=6),
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

devices = {
    "d7:8c:84:7d:6d:13": 4,
}

weights = {}

def callback(netkey, appkey, src: int, dst: int, opcode: int, parameters: bytes):
    if opcode == 0xc40131:
        mac_addr = Addr(parameters[:6])
        r_node_id = devices[str(mac_addr)]
        rssi = parameters[6] - 256
        pair = [src, r_node_id]
        pair.sort()
        hash_key = str(pair)
        if hash_key in weights:
            weights[hash_key] /= 2
            weights[hash_key] += rssi / 2
        else:
            weights[hash_key] = 1.0 * rssi
        
        print(pair, "%.02f"%weights[hash_key])


with MeshContext(netkeys=netkeys, appkeys=appkeys, devicekeys=devkeys, OnAccessMsg=callback) as ctx:
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
            continue
        for payload in payloads:
            packet = AdvertisingMessage.from_bytes(payload)
            if isinstance(packet, MeshMessage):
                # print(rssi, addr)
                ctx.decode_message(packet)
            elif isinstance(packet, MeshBeacon):
                pass
