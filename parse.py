from pwn import *
from zlib import crc32
import base64
import md5

MAGIC_HEADER = "\x30\x74\x74\x33\x72\x1a"

invert = lambda v: chr(ord(v) ^ 0xff)
rotate = lambda v: chr( int( bin(ord(v))[2:].zfill(8)[::-1], 2 ) )

def uppercase_decode(data, flag):
    flag = ''.join(rotate(v) for v in flag)
    data = list(data)

    for i, c in enumerate(flag):
        c = ord(c)
        for j in range(0, 8):
            p = i * 8 + j
            k = 1 << j
            if (c & k) == k:
                data[p] = data[p].upper()

    return ''.join(data)

def uppercase_variants(data, flag):
    h = []
    h.append(uppercase_decode(data, flag))

    flag2 = ''.join(invert(v) for v in flag)
    h.append(uppercase_decode(data, flag2))

    flag3 = ''.join(rotate(v) for v in flag)
    h.append(uppercase_decode(data, flag3))

    flag4 = ''.join(invert(rotate(v)) for v in flag)
    h.append(uppercase_decode(data, flag4))

    return h

def otter_crc32(data, type):
    h = crc32(data)
    if type == 1:
        return -h
    else:
        return 0x100000000 - h

def md5sum(data):
    return md5.new(data).hexdigest()

def str_to_hex(s):
    s = list(s)
    s = map(lambda v: '\\x%02x' % ord(v), s)
    return ''.join(s)

re_b64 = re.compile('^[a-zA-Z0-9/+=\x00]+$')
def is_b64(s):
    return re_b64.match(s) is not None

def parse_section(data):
    i = 0
    info = {}

    log.info('')
    log.info('========')
    info['name'] = data[i:i+8]; i += 8
    log.info('Section name: %s' % info['name'])

    info['data_length'] = u32(data[i:i+4]); i += 4
    info['crc32'] = u32(data[i:i+4]); i += 4
    info['crc32_type'] = u32(data[i:i+4]); i += 4
    assert info['crc32_type'] <= 1
    log.info('crc32 data(%d): %08x ' % (info['crc32_type'], info['crc32']))

    assert (info['data_length'] % 8) == 0
    info['header_length'] = info['data_length'] / 8
    info['header'] = data[i:i+info['header_length']]; i += info['header_length']

    data_b64 = data[i:i+info['data_length']]; i += info['data_length']

    my_crc32 = otter_crc32(info['header'] + data_b64, info['crc32_type'])
    log.info('crc32 of data: %08x' % my_crc32)
    info['actual_crc32'] = my_crc32

    # assert info['crc32'] == my_crc32

    info['length'] = i

    log.info('Header Length: %d' % info['header_length'])
    log.info('Data Length: %d' % info['data_length'])

    info['data'] = data_b64
    info['data'] = uppercase_decode(info['data'], info['header'])
    if info['name'] != 'OTHER\x00\x00\x00':
        assert is_b64(data_b64), data_b64
        log.info(info['data'])

        info['data'] = base64.b64decode(info['data'])
    log.info('========')

    return info


def parse(data, name, mtime):
    # check mtime
    info = {}
    i = 0

    # md5(data) == filename
    info['name'] = name
    info['md5_match'] = name == md5sum(data)
    log.info('md5 match: %d' % info['md5_match'])
    log.info('Length: %d' % len(data))

    info['magic'] = data[i:i+len(MAGIC_HEADER)]; i += len(MAGIC_HEADER)
    assert MAGIC_HEADER == info['magic']
    log.info('Magic: %s' % str_to_hex(info['magic']))

    info['num_of_sections'] = u32(data[i:i+4]); i += 4
    log.info('Number of sections: %d' % info['num_of_sections'])

    info['other_section_offset'] = u32(data[i:i+4]); i += 4
    log.info('Raw offset to the OTHER section containing the file description: %d' % info['other_section_offset'])

    # log.info((data[info['other_section_offset']:info['other_section_offset']+100]))

    info['creation_date'] = u32(data[i:i+4]); i += 4
    log.info('Creation date: %d' % info['creation_date'])
    info['creation_date_diff'] = abs(info['creation_date'] - mtime)
    log.info('Creation date diff: %d' % info['creation_date_diff'])

    # info['other_section'] = parse_section(data[info['other_section_offset']:])
    #
    # return info

    k = 1
    info['sections'] = []
    while i < len(data):
        log.info('')
        log.info('Section %d' % k)
        section = parse_section(data[i:])
        i += section['length']

        info['sections'].append(section)
        k += 1

    # are there more sections?
    info['actual_num_of_sections'] = len(info['sections'])

    return info
