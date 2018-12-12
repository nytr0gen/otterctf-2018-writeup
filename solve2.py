from parse import *
from os import path, listdir

def parse_file(pathname):
    mtime = int(path.getmtime(pathname))
    with open(pathname, 'rb') as f:
        data = f.read()

    info = parse(data, pathname[4:-4], mtime)
    return info

def main():
    context.log_level = 'error'

    files = []
    vars = []
    dir = list(os.listdir('otr/'))
    for k, name in enumerate(dir):
        pathname = 'otr/' + name
        log.info(pathname)
        if k % 100 == 0:
            print k

        info = parse_file(pathname)
        log.info('')

        for i, x in enumerate(info['sections']):
            if x['crc32'] != x['actual_crc32']:
                print 'got %s' % pathname
                print '[*] crc32 data: %08x' % x['crc32']
                vars.append(x['crc32'])
                print '[*] actual crc32: %08x' % x['actual_crc32']
                print ''

        files.append(info)

    # got e0e4b95aac5365c800f304a31985889a
    # [*] crc32 data(0): c7c455e1
    # [*] crc32 of data: a6688248

    # got d6a4a2ebd4f6418c3b064de26cc06a12
    # [*] crc32 data(0): f8ad0ba4
    # [*] crc32 of data: b8cfe1ab

    for k, info in enumerate(files):
        for i, x in enumerate(info['sections']):
            if x['crc32'] in vars:
                print k, pathname
                print x['name']
                print ''

    # CTF{M0r7y9uy}

if __name__ == '__main__':
    main()
