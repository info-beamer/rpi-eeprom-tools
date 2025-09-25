import struct, textwrap, time, re, binascii, datetime
try:
    from lz4.frame import decompress as decompress_lz4
except ImportError:
    decompress_lz4 = None
try:
    from cStringIO import StringIO as BytesIO
    to_byte = chr
    struct_bytes = str
    range = xrange
except ImportError:
    from io import BytesIO
    to_byte = lambda v: bytes((v,))
    struct_bytes = bytearray
from collections import OrderedDict
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5

IMAGE_TYPES = {
    'pi4': {
        'image_size': 512 * 1024,
        'reserved': 4096,
    },
    'pi5': {
        'image_size': 2048 * 1024,
        'reserved': 4096,
    },
}

MAGIC_BITS = 0x55aaf00f
MAGIC_MASK = 0xfffff00f

MAGIC_FILL = 0xee0

class FormatError(Exception):
    pass

def align_up(v, a):
    return (v + a - 1) & ~(a - 1)

# CK (?) compression/decompression.
# Fully based on work by Hristo Venev
# See https://git.venev.name/hristo/rpi-eeprom-compress/

def decompress_ck(raw):
    out = BytesIO()
    outbuf = bytearray(b'\x00' * 256)
    out_i = 0
    h = SHA256.new()

    def outp(c):
        outbuf[out_i] = c
        out.write(to_byte(c))
        h.update(to_byte(c))
        return (out_i + 1) & 0xff

    compressed = raw[:-32]
    checksum = raw[-32:]
    inp = iter(c for c in compressed)

    try:
        while 1:
            cmd = next(inp)
            for i in range(8):
                if cmd & 1:
                    offset = next(inp) + 1
                    length = next(inp) + 1
                    for i in range(length):
                        out_i = outp(outbuf[(out_i - offset) & 0xff])
                else:
                    out_i = outp(next(inp))
                cmd >>= 1
    except StopIteration:
        pass
    if h.digest() != checksum:
        raise FormatError("Invalid checksum")
    return out.getvalue()

try:
    import ctypes, os
    compressor = ctypes.CDLL(os.path.join(os.path.dirname(__file__), 'compress.so'))
    compressor.compress.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
    compressor.compress.restype = ctypes.c_int
    def compress_ck(input_data):
        input_data = bytearray(input_data)
        data = (ctypes.c_uint8 * len(input_data))(*input_data)
        out_len = int(len(input_data) * 1.1) # ??
        out = (ctypes.c_uint8 * out_len)()
        res = compressor.compress(data, len(data), out, out_len)
        if res < 0:
            raise FormatError("Cannot compress data")
        return bytearray(out[:res]) + SHA256.new(input_data).digest()
except:
    def compress_ck(raw):
        inp = BytesIO(raw)
        out = BytesIO()
        while 1:
            buf = inp.read(8)
            if not buf:
                break
            out.write(b'\x00')
            out.write(buf)
        return bytearray(out.getvalue() + SHA256.new(raw).digest())


class Chunk(object):
    def __init__(self, name, chunk_type, original_offset=None, raw=None):
        self._name = name
        self._original_offset = original_offset
        self._chunk_type = chunk_type
        self._raw = raw

    @classmethod
    def create(cls, name):
        return cls(name, cls.MAGIC)

    @staticmethod
    def get_subclass_for(chunk_type):
        return {
            ChunkBoot.MAGIC: ChunkBoot,
            ChunkConf.MAGIC: ChunkConf,
            ChunkFileCK.MAGIC: ChunkFileCK,
            ChunkFileLZ4.MAGIC: ChunkFileLZ4
        }[chunk_type]

    @property
    def image_size(self):
        return 24 + len(self._raw)

    @property
    def name(self):
        return self._name

    def get_raw_bin(self):
        return self._raw

    def set_raw_bin(self, raw):
        self._raw = raw
        return self

    def get_raw_text(self):
        return self._raw.decode('utf8')

    def set_raw_text(self, raw_text):
        return self.set_raw_bin(raw_text.encode('utf8'))

    def __repr__(self):
        return '<%-12s: %-16s %6d @ 0x%08x / %6d>' % (
            type(self).__name__, self.name or '<bootsys>',
            len(self._raw), self._original_offset, self._original_offset,
        )

class ChunkBoot(Chunk):
    MAGIC = 0x0

class ChunkFile(Chunk):
    pass

class ChunkFileCK(ChunkFile):
    MAGIC = 0x330

    def get_file(self):
        return decompress_ck(self._raw)

    def set_file(self, data):
        compressed = compress_ck(data)
        self.set_raw_bin(compressed)

class ChunkFileLZ4(ChunkFile):
    MAGIC = 0x440

    def get_file(self):
        if decompress_lz4 is None:
            raise FormatError("No LZ4 decompressor available")
        raw = bytes(self._raw)
        data, chk = raw[:-32], raw[-32:]
        decompressed = decompress_lz4(data)
        if SHA256.new(decompressed).digest() != chk:
            raise FormatError("Invalid checksum")
        return decompressed

    def set_file(self, data):
        raise NotImplementedError("LZ4 compression not implemented")

class ChunkConf(Chunk):
    MAGIC = 0x110

    def set_signature(self, key, data, sign_time=None):
        dgst = SHA256.new(data)
        sig = PKCS1_v1_5.new(key).sign(dgst)
        return self.set_text(u"""
            %(sha)s
            ts: %(ts)d
            rsa2048: %(rsa)s
        """ % dict(
            sha = dgst.hexdigest(),
            ts = time.time() if sign_time is None else sign_time,
            rsa = binascii.hexlify(sig).decode('utf8'),
        ))
        return self

    def set_key(self, key):
        if key.n.bit_length() != 2048:
            raise FormatError("RSA key size must be 2048")
        def to_little_bytes(n, length):
            h = '%x' % n
            s = ('0'*(len(h) % 2) + h).zfill(length*2)
            return binascii.unhexlify(s)[::-1]
        return self.set_raw_bin(to_little_bytes(key.n, 256) + to_little_bytes(key.e, 8))

    def set_text(self, text):
        return self.set_raw_text(textwrap.dedent(text).lstrip())

class Reader(object):
    def __init__(self, source):
        self._chunks = OrderedDict()
        self._type = None
        for name, chunk_type, offset, raw in self._parse_chunks(source):
            self._chunks[name] = Chunk.get_subclass_for(chunk_type)(
                name, chunk_type, offset, raw
            )

    @property
    def image_type(self):
        return self._type

    @property
    def image_size(self):
        return IMAGE_TYPES[self._type]['image_size']

    @property
    def reserved(self):
        return IMAGE_TYPES[self._type]['reserved']

    def _parse_chunks(self, source):
        raw = bytearray(source.read())
        for type, type_info in IMAGE_TYPES.items():
            if len(raw) == type_info['image_size']:
                self._type = type
        if self._type is None:
            raise FormatError('Unknown EEPROM type')
        offset = 0
        while offset < self.image_size:
            magic, length = struct.unpack_from('>LL', raw, offset)
            if magic == 0 or magic == 0xffffffff:
                break
            if magic & MAGIC_MASK != MAGIC_BITS:
                raise FormatError('EEPROM is corrupted')
            name = raw[offset + 8: offset + 20]
            file_offset = offset + 20 + 4
            chunk_type = magic & ~MAGIC_MASK
            if chunk_type != MAGIC_FILL:
                yield (
                    name.strip(b'\x00\xff').decode('utf8'),
                    magic & ~MAGIC_MASK,
                    offset, raw[file_offset:file_offset+length-12-4],
                )
            offset = align_up(offset + 8 + length, 8)
        if self.version != self.bootloader_version[:8]:
            raise FormatError('Mismatch in version numbers')

    @property
    def version(self):
        m = re.search(b"VERSION:([0-9a-f]{8})", self._chunks[''].get_raw_bin()) # eww
        if m is None:
            raise FormatError("Cannot find version")
        return m.group(1).decode('utf8')

    @property
    def bootloader_version(self):
        m = re.search(b"BVER[\x80|\x8c]\0\0\0[\x80|\x8c]\0\0\0([0-9a-f]{40})", self._chunks[''].get_raw_bin()) # eww
        if m is None:
            raise FormatError("Cannot find bootloader version")
        return m.group(1).decode('utf8')

    @property
    def date(self):
        m = re.search(b"DATE: ([0-9]{4})/([0-9]{2})/([0-9]{2})", self._chunks[''].get_raw_bin())
        if m is None:
            raise FormatError("Cannot find date")
        return datetime.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))

    def get(self, name):
        return self._chunks.get(name)

    def __iter__(self):
        for name, chunk in self._chunks.items():
            yield chunk

    def create_writer(self):
        return Writer(self.image_size, self.reserved)


class Writer(object):
    def __init__(self, image_size, reserved):
        self._offset = 0
        self._image_size = image_size
        self._reserved = reserved
        self._image = bytearray(b'\xff' * self._image_size)

    def append(self, chunk):
        raw = chunk.get_raw_bin()
        self._offset, offset = align_up(self._offset + chunk.image_size, 8), self._offset
        if self.free < 0:
            raise FormatError("Not space left: Exceeded available space by {} bytes".format(-self.free))
        struct.pack_into(">LL12sL%ds" % len(raw), self._image, offset,
            MAGIC_BITS | chunk._chunk_type,
            len(raw) + 12+4,
            chunk._name.encode('utf8'),
            0,
            struct_bytes(raw),
        )

    def fill_until(self, offset):
        struct.pack_into(">LL", self._image, self._offset,
            MAGIC_BITS | MAGIC_FILL,
            offset - self._offset - 8,
        )
        assert offset % 8 == 0
        self._offset = offset

    def fill(self, size):
        self.fill_until(self._offset + size)

    @property
    def offset(self):
        return self._offset

    @property
    def free(self):
        return self._image_size - self._reserved - self._offset

    @property
    def img(self):
        return self._image

    def sig(self, sign_time=None):
        return (textwrap.dedent(u"""
            %(sha256)s
            ts: %(ts)d
        """).lstrip() % dict(
            sha256 = SHA256.new(self._image).hexdigest(),
            ts = time.time() if sign_time is None else sign_time,
        )).encode('utf8')

    def write_img(self, dest):
        dest.write(self.img)

    def write_sig(self, dest, sign_time=None):
        dest.write(self.sig(sign_time))
