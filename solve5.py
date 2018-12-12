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

        if info['creation_date_diff'] > 3601:
            print info['name']
            # print info
            dt = datetime.fromtimestamp(info['creation_date'])
            # CTF{HH:MM:SS DD/MM/YYYY at Jerusalem local time}
            print 'CTF{%s}' % dt.strftime('%I:%M:%S %d/%m/%Y')
            print ''

if __name__ == '__main__':
    main()
