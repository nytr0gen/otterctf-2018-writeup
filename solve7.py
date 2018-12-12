from parse import *
from os import path, listdir
from datetime import datetime

def parse_file(pathname):
    mtime = int(path.getmtime(pathname))
    with open(pathname, 'rb') as f:
        data = f.read()

    info = parse(data, pathname[4:-4], mtime)
    return info

def main():
    context.log_level = 'error'

    dir = list(os.listdir('otr/'))
    for k, name in enumerate(dir):
        pathname = 'otr/' + name
        print k, pathname

        info = parse_file(pathname)
        log.info('')

        if not info['md5_match']:
            print info['name']
            for s in info['sections']:
                if s['name'] == 'OTHER\x00\x00\x00':
                    print s

if __name__ == '__main__':
    main()
