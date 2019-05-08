from btmesh.Context import *
from btmesh.Message import *
from btmesh.Util import *

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

devkeys = [
    DeviceKey.fromString(
        'E0CD4044F42C1E221BD4CBB8001737E5', nodeid=2),
    DeviceKey.fromString(
        '8200E049831EF702D003AD7573A2D081', nodeid=4),
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
    "d1:47:5b:05:73:22": 2,
}

weights = {}
nodes = set()

for _, nodeid in devices.items():
    nodes.add(nodeid)

counter = 0


def callback(netkey, appkey, src: int, dst: int, opcode: int, parameters: bytes):
    global counter
    if opcode == 0xc40131:
        nodes.add(src)
        counter += 1
        mac_addr = Addr(parameters[:6])
        # print(mac_addr)
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
        print('%04x <-> %04x : %d' % (src, r_node_id, rssi))


with MeshContext(netkeys=netkeys, appkeys=appkeys, devicekeys=devkeys, OnAccessMsg=callback) as ctx:
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('192.168.113.250', 10010))
    f = sock.makefile()

    import time

    end_time = time.time() + 10

    try:
        while True:
            l = f.readline()
            try:
                rssi, addr, data = eval(l)
            except SyntaxError:
                print(l)
                continue
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
    except KeyboardInterrupt:
        print('stopping...')
        pass
    sock.close()

    import networkx as nx
    g = nx.Graph()
    ws = set()

    for node in nodes:
        g.add_node(node, node_color='blue')
    for k, weight in weights.items():
        node_1, node_2 = eval(k)
        g.add_edge(node_1, node_2, weight=((128+weight)/128)
                   ** 2, label='%.01f' % weight)

    # pos = nx.spectral_layout(g)
    pos = nx.spring_layout(g)
    nx.draw(g, pos, with_labels=True)
    labels = nx.get_edge_attributes(g, 'label')
    nx.draw_networkx_edge_labels(g, pos, edge_labels=labels)
    import matplotlib.pyplot as plt
    plt.show()
