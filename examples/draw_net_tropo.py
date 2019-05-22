import os
import sys
import json
import time
import getopt

from btmesh import Context
from btmesh import Message
from btmesh import Util

from bluepy import btle


def load_network_json(filename):
    netkeys = list()
    appkeys = list()
    devkeys = list()
    devlist = dict()
    with open(filename, "r") as f:
        network = json.load(f)
        print("loaded network: " + network["meshName"])

        for netkey in network["netKeys"]:
            netkeys.append(Util.NetworkKey.fromString(
                netkey["key"], iv_index=netkey["index"], tag=netkey["name"]))

        for appkey in network["appKeys"]:
            appkeys.append(Util.ApplicationKey.fromString(
                appkey["key"], iv_index=appkey["index"], tag=appkey["name"]))

        for node in network["nodes"]:
            nodeid = int(node["unicastAddress"], 16)
            devkeys.append(Util.DeviceKey.fromString(
                node["deviceKey"], nodeid=nodeid))
            devlist[str(Util.Addr.from_string(node["UUID"][12:24]))] = nodeid

        return netkeys, appkeys, devkeys, devlist


def print_usage():
    print("usage: draw_net_tropo.py --net <net.json>")
    sys.exit(2)


def bin_to_hex_str(s):
    return ' '.join(map('{:02x}'.format, s))


output_position = '>/dev/null'
# output_position = ''


def send(msg: bytes):
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


devices = dict()
weights = dict()


def callback(netkey, appkey, src: int, dst: int, opcode: int, parameters: bytes):
    if opcode == 0xc40131 and len(parameters) == 7:
        mac_addr = Util.Addr(parameters[:6])
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
        print('RSSI Updated: %04x <-> %04x : %d' % (src, r_node_id, rssi))


def load_net(argv, OnMsg=None):
    global devices
    try:
        opts, _ = getopt.getopt(
            argv, "hn:i:", ["--help", "--net=", "--image="])
    except getopt.GetoptError:
        print_usage()

    networkfile = None
    imagefile = None

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print_usage()
        elif opt in ("-n", "--net"):
            networkfile = arg
        elif opt in ("-i", "--image"):
            imagefile = arg

    nkeys, akeys, dkeys, devices = load_network_json(networkfile)

    return Context.MeshContext(netkeys=nkeys, appkeys=akeys, devicekeys=dkeys, OnAccessMsg=OnMsg), imagefile


observer_weights = {}


class ScanDelegate(btle.DefaultDelegate):
    def __init__(self, ctx):
        btle.DefaultDelegate.__init__(self)
        self._ctx = ctx

    def handleDiscovery(self, dev, isNewDev, isNewData):
        if isNewData:
            temp = dev.getValueText(0x2a)
            if temp is not None:
                addr = str(Util.Addr.from_string(dev.addr))
                if addr in devices.keys():
                    nodeid = devices[addr]
                    if nodeid in observer_weights:
                        observer_weights[nodeid] /= 2
                        observer_weights[nodeid] += dev.rssi / 2
                    else:
                        observer_weights[nodeid] = dev.rssi
                self._ctx.decode_message(bytes.fromhex(temp))


def main(argv):
    ctx, out_img = load_net(argv, OnMsg=callback)

    # 发送创建拓扑图指令
    make_tropo_msg = ctx.encode_message(
        0x100, 0xc000, 63, 5, 0xc40131, b'\x3c')
    send(make_tropo_msg)

    # 开始监听
    scanner = btle.Scanner().withDelegate(ScanDelegate(ctx))
    try:
        print("Start scanning...")
        print("Press Ctrl+C to stop scanning")

        # 等待用户案件退出
        while True:
            scanner.scan(10.0, passive=True)
    except KeyboardInterrupt:
        print()
        print('Stopping...')
        pass

    print()
    print("Preparing graph...")
    import networkx as nx
    g = nx.Graph()

    g.add_node('$Observer$')
    for _, v in devices.items():
        g.add_node("$%04X$" % v)

    import matplotlib.pyplot as plt

    for k, weight in observer_weights.items():
        g.add_edge('$Observer$', "$%04X$" % k, weight=1-abs(weight) /
                   128.0, label='%.01f' % weight)

    for k, weight in weights.items():
        node_1, node_2 = eval(k)
        g.add_edge("$%04X$" % node_1, "$%04X$" % node_2, weight=1-abs(
            weight)/128.0, label='%.01f' % weight)

    # pos = nx.spectral_layout(g)
    pos = nx.spring_layout(g)

    e = nx.get_edge_attributes(g, 'weight')

    ecolor = [int(e[k]*100) for k in g.edges()]

    nx.draw(g, pos, with_labels=True, node_size=800,
            # or cool or spring or winter or autumn
            node_color=range(len(devices) + 1), cmap=plt.cm.summer,
            edge_color=ecolor, edge_cmap=plt.cm.plasma)

    labels = nx.get_edge_attributes(g, 'label')

    nx.draw_networkx_edge_labels(
        g, pos, edge_labels=labels)

    print("write to image file " + out_img)
    # plt.tight_layout()
    plt.savefig(out_img)
    import stat
    os.chmod(out_img, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP |
             stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH)


if __name__ == "__main__":
    main(sys.argv[1:])
