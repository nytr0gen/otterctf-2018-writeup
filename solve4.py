from parse import *
from os import path, listdir
from datetime import datetime
import random
import base64
import errno
import os

def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

def parse_file(pathname):
    mtime = int(path.getmtime(pathname))
    with open(pathname, 'rb') as f:
        data = f.read()

    info = parse(data, pathname[4:-4], mtime)
    return info

files = []
def main():
    # context.log_level = 'error'

    dir = list(os.listdir('otr/'))
    for k, name in enumerate(dir):
        pathname = 'otr/' + name
        log.info(pathname)
        print k, pathname

        info = parse_file(pathname)
        log.info('')

        # files.append(info)

        dirpath = 'decoded/%s' % name[:-4]
        mkdir_p(dirpath)
        for i, s in enumerate(info['sections']):
            sname = '%s/%d_%s' % (dirpath, i, s['name'].replace('\x00', ''))
            with open(sname, 'wb') as f:
                f.write(s['data'])

if __name__ == '__main__':
    main()
