from parse import *
from os import path, listdir
from datetime import datetime
import random
import base64

def dist(x, y):
    s = 0
    for a, b in zip(x, y):
        s += (a != b)

    return s

# CTF{a358f694d1e5113ccd1a9ad7f1385549}
def solve1_parse_file(pathname):
    with open(pathname, 'rb') as f:
        data = f.read()

    for i in range(9, len(data)):
        s = data[i-9:i]
        if (s[-4:-1] == '\x00\x00\x00'
            and s[-1] != '\x00'
            and is_b64(s[0:5])
            and dist(s[0:5], 'lutra') < 5
        ):
            print pathname, s

def main():
    for name in os.listdir('otr/'):
        pathname = 'otr/' + name
        solve1_parse_file(pathname)

if __name__ == '__main__':
    main()
