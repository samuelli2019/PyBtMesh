from Context import *
from Message import *
from Util import *

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

devices = {
    "f5:b6:b8:39:e1:88": 2,
    # "ca:f8:22:f1:4d:f4": 0x0a,
    # "d2:dc:87:6c:83:5c": 0x0c,
    # "c4:2b:9d:f7:e0:2f": 0x26,
    "df:ae:fe:10:f0:25": 0x28,
    "dd:07:d9:fe:3d:59": 0x2d,
    "e9:86:a0:bd:83:15": 100,
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
            print('find new connection: src %04x to dst %04x rssi %d' % (src, r_node_id, rssi))
            weights[hash_key] = 1.0 * rssi
        
        # print(pair, "%.02f"%weights[hash_key])


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
        pass
    sock.close()
    
    import networkx as nx
    g = nx.Graph()
    ws = set()

    for node in nodes:
        g.add_node(node, node_color='blue')
    for k, weight in weights.items():
        node_1, node_2 = eval(k)
        g.add_edge(node_1, node_2, weight=((128+weight)/128)**2, label='%.01f'%weight)

    pos = nx.spectral_layout(g)
    nx.draw(g, pos, with_labels=True)
    labels = nx.get_edge_attributes(g, 'label')
    nx.draw_networkx_edge_labels(g, pos, edge_labels=labels)
    import matplotlib.pyplot as plt
    plt.show()

