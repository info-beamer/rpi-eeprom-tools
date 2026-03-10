# Reads the bootconf.txt at boot live from the EEPROM.
import os
import fcntl
import struct
import array
from collections import namedtuple

DEVICE_FILE_NAME = "/dev/vcio"
IOCTL_MBOX_PROPERTY = 0xC0046400

VC_MAILBOX_ERROR = 0x80000000

TAG_GET_EEPROM_PACKET = 0x00030096
TAG_GET_EEPROM_AB_PARAMS = 0x00030099

RPI_EEPROM_AB_ERROR_NO_ERROR           = 0
RPI_EEPROM_AB_ERROR_FAILED             = 1
RPI_EEPROM_AB_ERROR_INVALID_PARTITION  = 2
RPI_EEPROM_AB_ERROR_HASH_MISMATCH      = 3
RPI_EEPROM_AB_ERROR_BUSY               = 4
RPI_EEPROM_AB_ERROR_UPDATE             = 5
RPI_EEPROM_AB_ERROR_UNCOMMITTED        = 6
RPI_EEPROM_AB_ERROR_INVALID_ARG        = 7
RPI_EEPROM_AB_ERROR_LENGTH             = 8
RPI_EEPROM_AB_ERROR_ERASE              = 9
RPI_EEPROM_AB_ERROR_WRITE              = 10
RPI_EEPROM_AB_ERROR_ALREADY_COMMITTED  = 11
RPI_EEPROM_AB_ERROR_SPI_GPIO_ERROR     = 12
RPI_EEPROM_AB_ERROR_NO_PARTITIONING    = 13

RPI_EEPROM_AB_UPDATE_PACKET_MAX_SIZE = 256*1024

MAGIC_BITS = 0x55aaf00f
MAGIC_MASK = 0xfffff00f

FILL_MAGIC = 0xEE0
CONF_MAGIC = 0x110

PARTITION_A = 1
PARTITION_B = 2

PARTITION_OFFSET = 64*1024
PARTITION_SIZE = 988*1024

def align_up(v, a):
    return (v + a - 1) & ~(a - 1)

class FirmwareError(Exception):
    def __init__(self, code):
        self.code = code
        super(FirmwareError, self).__init__("VC Error %d" % (code,))

class Firmware(object):
    def __init__(self):
        self._fd = os.open(DEVICE_FILE_NAME, os.O_RDWR)

    def close(self):
        os.close(self._fd)

    def _mbox_property(self, buf):
        fcntl.ioctl(self._fd, IOCTL_MBOX_PROPERTY, buf, True)
        header = struct.unpack_from("<5L", buf, 0)
        code = header[1]
        tag_req_resp_size = header[4]
        if not (code & VC_MAILBOX_ERROR) or not (tag_req_resp_size & VC_MAILBOX_ERROR):
            return -1
        return 0

    Params = namedtuple("Params", "partition committed tryboot partition_at_boot committed_at_boot")
    def params(self):
        msg_size = 20 + 5*4 + 4
        msg = array.array('B', b'\x00' * msg_size)

        struct.pack_into("<5L", msg, 0,
            # struct firmware_update_get_ab_params_msg(size=msg_size) {
                # struct firmware_msg_header (size=20) {
                    msg_size,
                    0,
                    TAG_GET_EEPROM_AB_PARAMS,
                    5*4,
                    0,
                # }
            # 5 x uint32_t
            # end_tag - already zero due to initialization
            # }
        )

        rc = self._mbox_property(msg)
        if rc < 0:
            raise RuntimeError("Mailbox property call failed")

        error = struct.unpack_from("<L", msg, 20)[0]
        if error & VC_MAILBOX_ERROR:
            raise FirmwareError(error & ~VC_MAILBOX_ERROR)
        
        return self.Params(*struct.unpack_from("<5L", msg, 20))

    def read(self, address, size):
        data_size = align_up(size, 4)
        if data_size > RPI_EEPROM_AB_UPDATE_PACKET_MAX_SIZE:
            raise ValueError("Invalid length")

        msg_size = 20 + 8 + data_size + 4
        msg = array.array('B', b'\x00' * msg_size)

        struct.pack_into("<5L2L", msg, 0,
            # struct firmware_update_packet_msg (size=msg_size) {
                # struct firmware_msg_header (size=20) {
                    msg_size,
                    0,
                    TAG_GET_EEPROM_PACKET,
                    8 + data_size,
                    0,
                # }
            # 
            address,
            data_size,
            # data
            # end_tag - already zero due to initialization
            # }
        )

        rc = self._mbox_property(msg)
        if rc < 0:
            raise RuntimeError("Mailbox property call failed")

        error = struct.unpack_from("<L", msg, 20)[0]
        if error & VC_MAILBOX_ERROR:
            raise FirmwareError(error & ~VC_MAILBOX_ERROR)

        data_offset = 28
        return msg[data_offset:data_offset + size].tostring()

    ChunkInfo = namedtuple('ChunkInfo', 'type offset size')
    def iter_chunks(self, start=0, end=2048*1024):
        offset = start
        while offset < end:
            magic, length = struct.unpack('>LL', self.read(offset, 8))
            if magic == 0 or magic == 0xFFFFFFFF:
                break
            if magic & MAGIC_MASK != MAGIC_BITS:
                raise RuntimeError('EEPROM is corrupted at offset 0x{:X}'.format(offset))

            chunk_type = magic & ~MAGIC_MASK
            name = self.read(offset + 8, 12)
            yield (
                name.strip(b'\x00\xff').decode('utf8'),
                self.ChunkInfo(
                    chunk_type,
                    offset + 24,
                    length - 16,
                )
            )

            # Align offset for next chunk
            offset = align_up(offset + 8 + length, 8)

class FakeFirmware(Firmware):
    def __init__(self):
        pass
    def close(self):
        pass
    def params(self):
        return self.Params(1, 1, 0, 1, 1)
    def read(self, offset, size):
        with open('pieeprom.upd', 'rb') as f:
            f.seek(offset)
            return f.read(size)

if __name__ == "__main__":
    if os.path.exists('pieeprom.upd'):
        f = FakeFirmware()
    else:
        f = Firmware()

    try:
        p = f.params()
        offset = PARTITION_OFFSET + (
            0 if p.partition_at_boot == PARTITION_A else PARTITION_SIZE
        )
    except FirmwareError as err:
        if err.code == RPI_EEPROM_AB_ERROR_NO_PARTITIONING:
            offset = 0
        else:
            raise

    size = PARTITION_SIZE

    chunks = dict(f.iter_chunks(offset, offset+size))
    config = chunks['bootconf.txt']
    print(f.read(config.offset, config.size).decode('utf8'))
    f.close()
