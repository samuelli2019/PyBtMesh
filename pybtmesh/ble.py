class BleAdvertisingType(int):
    def __new__(cls, *args, **kwargs):
        if isinstance(args, tuple) and len(args) == 2 and isinstance(args[1], str):
            cls.__str__ = lambda self: args[1]
            return int.__new__(cls, *args[:1], **kwargs)
        else:
            return int.__new__(cls, *args, **kwargs)


BleAdv_Flags = BleAdvertisingType(
    0x01, 'Flags')

BleAdv_Incomplete16bitService = BleAdvertisingType(
    0x02, 'Incomplete List of 16-bit Service Class UUIDs')

BleAdv_Complete16bitService = BleAdvertisingType(
    0x03, 'Complete List of 16-bit Service Class UUIDs')

BleAdv_Incomplete32bitService = BleAdvertisingType(
    0x04, 'Incomplete List of 32-bit Service Class UUIDs')

BleAdv_Complete32bitService = BleAdvertisingType(
    0x05, 'Complete List of 32-bit Service Class UUIDs')

BleAdv_Incomplete128bitService = BleAdvertisingType(
    0x06, 'Incomplete List of 128-bit Service Class UUIDs')

BleAdv_Complete128bitService = BleAdvertisingType(
    0x07, 'Complete List of 128-bit Service Class UUIDs')

BleAdv_ShortName = BleAdvertisingType(
    0x08, 'Shortened Local Name')

BleAdv_Name = BleAdvertisingType(
    0x09, 'Complete Local Name')

BleAdv_TxPower = BleAdvertisingType(
    0x0a, 'Tx Power Level')

BleAdv_DevType = BleAdvertisingType(
    0x0d, 'Class of Device')

# BleAdv_ = BleAdvertisingType(
#     0x0e, 'Simple Pairing Hash C/C-192')
# BleAdv_ = BleAdvertisingType(
#     0x0f, 'Simple Pairing Randomizer R/R-192')
# BleAdv_ = BleAdvertisingType(
#     0x10, 'Device ID/Security Manager TK Value')
# BleAdv_ = BleAdvertisingType(
#     0x11, 'Security Manager Out of Band Flags')
# BleAdv_ = BleAdvertisingType(
#     0x12, 'Slave Connection Interval Range')

BleAdv_16bitSolicitData = BleAdvertisingType(
    0x14, 'List of 16-bit Service Solicitation UUIDs')

BleAdv_128bitSolicitData = BleAdvertisingType(
    0x15, 'List of 128-bit Service Solicitation UUIDs')

BleAdv_16bitData = BleAdvertisingType(
    0x16, 'Service Data/Service Data - 16-bit UUID')

# BleAdv_ = BleAdvertisingType(
#     0x17, 'Public Target Address')
# BleAdv_ = BleAdvertisingType(
#     0x18, 'Random Target Address')
# BleAdv_ = BleAdvertisingType(
#     0x19, 'Appearance')
# BleAdv_ = BleAdvertisingType(
#     0x1a, 'Advertising Interval')
# BleAdv_ = BleAdvertisingType(
#     0x1b, 'LE Bluetooth Device Address')
# BleAdv_ = BleAdvertisingType(
#     0x1c, 'LE Role')
# BleAdv_ = BleAdvertisingType(
#     0x1d, 'Simple Pairing Hash C-256')
# BleAdv_ = BleAdvertisingType(
#     0x1e, 'Simple Pairing Randomizer R-256')
# BleAdv_ = BleAdvertisingType(
#     0x1f, 'List of 32-bit Service Solicitation UUIDs')
# BleAdv_ = BleAdvertisingType(
#     0x20, 'Service Data - 32-bit UUID')
# BleAdv_ = BleAdvertisingType(
#     0x21, 'Service Data - 128-bit UUID')
# BleAdv_ = BleAdvertisingType(
#     0x22, 'LE Secure Connections Confirmation Value')
# BleAdv_ = BleAdvertisingType(
#     0x23, 'LE Secure Connections Random Value')
# BleAdv_ = BleAdvertisingType(
#     0x24, 'URI')
# BleAdv_ = BleAdvertisingType(
#     0x25, 'Indoor Positioning')
# BleAdv_ = BleAdvertisingType(
#     0x26, 'Transport Discovery Data')
# BleAdv_ = BleAdvertisingType(
#     0x27, 'LE Supported Features')
# BleAdv_ = BleAdvertisingType(
#     0x28, 'Channel Map Update Indication')

BleAdv_PBADV = BleAdvertisingType(
    0x29, 'PB-ADV')

BleAdv_MeshMsg = BleAdvertisingType(
    0x2a, 'Mesh Message')

BleAdv_MeshBeacon = BleAdvertisingType(
    0x2b, 'Mesh Beacon')

# BleAdv_ = BleAdvertisingType(
#     0x3d, '3D Information Data')
# BleAdv_ = BleAdvertisingType(
#     0xff, 'Manufacturer Specific Data')

