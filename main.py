from parse import *
from os import path, listdir
from datetime import datetime
import random
import base64

def re_solve6():
    base = 'N:'
    variants = set()

    v = base64.b64encode(base).replace('=', '').lower()
    variants.add(v)
    variants.add(v[1:-1])

    for i in range(0, 255):
        for j in range(0, 255):
            v = chr(i) + base.lower() + chr(j)
            v = base64.b64encode(v).replace('=', '').lower()

            variants.add(v)
            variants.add(v[1:-1])

    exp = '|'.join(re.escape(v) for v in variants)
    print exp
    exp = re.compile(exp, re.IGNORECASE)

    return exp

# for v in `grep -r 'N\:' otr | awk '{print $3}'`; do
#   echo $v
#   xxd $v| grep -C10  'N:'
#   echo
# done
# CTF{RicKShiK}
def solve6():
    re_variants = re_solve6()
    for name in os.listdir('otr/'):
        pathname = 'otr/' + name
        with open(pathname, 'rb') as f:
            data = f.read()
        if re_variants.match(data) is not None:
            print pathname

def parse_file(pathname):
    mtime = int(path.getmtime(pathname))
    with open(pathname, 'rb') as f:
        data = f.read()

    info = parse(data, pathname[4:-4], mtime)
    return info

files = []
def main():
    # solve2()
    # return
    # pathname = 'otr/e3c991061dcd0add2f669be17bf8539d.otr'
    # info = parse_file(pathname)
    # # print info
    # return

    dir = list(os.listdir('otr/'))
    dir = random.sample(dir, 20)
    # dir = ['e3c991061dcd0add2f669be17bf8539d.otr']
    # dir = ['d6a4a2ebd4f6418c3b064de26cc06a12.otr']
    for name in dir:
        pathname = 'otr/' + name
        log.info(pathname)

        info = parse_file(pathname)
        log.info('')

        files.append(info)
        # print info['other_section']['data']

    # solve7(files)
    # solve5(files)

if __name__ == '__main__':
    main()
