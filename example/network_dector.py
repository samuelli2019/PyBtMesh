import sys
import uuid
import socket
import bitstring


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
        print('i != total_len')

def get_dev_info(dev):
    dev_name, dev_uuid, dev_networkid = None, None, None
    for advtype, description, value in dev.getScanData():
        if advtype == 0x09:
            dev_name = value
        elif advtype == 0x16:
            service_data = bindata(value)
            service_uuid = int.from_bytes(service_data[:2], 'little')
            if service_uuid == 0x1827:
                dev_uuid = service_data[2:18]
            elif service_uuid == 0x1828:
                dev_networkid = service_data[2:]

    return dev_name, dev_uuid, dev_networkid


def is_mesh_device(device):
    _, uuid0, network_id = get_dev_info(device)
    return uuid0 or network_id is not None


class MeshDevice:
    def __init__(self, device):
        self.rssi = device.rssi
        self.addr = device.addr
        self.name, self.uuid0, self.network_id = get_dev_info(device)
        assert self.uuid0 or self.network_id is not None

    @property
    def isProvisioned(self):
        return self.network_id is not None

    @property
    def uuid(self):
        return str(uuid.UUID(bytes=self.uuid0))

    def __str__(self):
        if self.isProvisioned:
            return 'Y %3ddB\t%s\t%s\t%s' % (self.rssi, (self.name or 'UnNamed').rjust(16, ' '), self.addr, hex_to_str(self.network_id))
        else:
            return 'N %3ddB\t%s\t%s\t%s' % (self.rssi, (self.name or 'UnNamed').rjust(16, ' '), self.addr, self.uuid)


def print_hex(s):
    r = s
    if isinstance(s, str):
        print(s)
    else:
        for c in r:
            print('%02x' % c, end=' ')



mesh_devices = list()

for dev in devices:
    if is_mesh_device(dev):
        mesh_devices.append(MeshDevice(dev))

for dev in mesh_devices:
    print(dev)
