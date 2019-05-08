import bitstring


class ProxyEncoder:
    STRUCT = 'uint:2, uint:6, bytes'
    SAR_COMPLETE = 0x00
    SAR_FIRST = 0x01
    SAR_CONTINUA = 0x02
    SAR_LAST = 0x03

    TYPE_NETWORK = 0x00
    TYPE_BEACON = 0x01
    TYPE_PROXY_CONF = 0x02
    TYPE_PROV = 0x03

    def __init__(self, mtu: int):
        self._mtu = mtu

    def encode(self, data, data_type=TYPE_NETWORK):
        if len(data) < self._mtu:
            yield bitstring.pack(self.STRUCT, self.SAR_COMPLETE, data_type, data).bytes
        else:
            pass
