#!/usr/bin/env python3
'''
Search firmware file for a pattern starting with \x00\x02 so that it can be
re-used by ROP chains in need of an AF_INET value for their sockaddr_in structures.

The script will print the corresponding TCP port that the device will try connecting
to if a specific address is used to construct the sockaddr_in struct.

Author: Quentin Kaiser <quentin@ecos.wtf>
'''
import sys
import re
import struct

LOAD_ADDR = 0x80004000

def hunt(firmware_filename):
    with open(firmware_filename, "rb") as f:
        content = f.read()
        for match in re.finditer(b"\x00\x02([\x00-\xFF][\x00-\xFF])", content):
            idx = match.start()
            if idx % 4 == 0:
                port = struct.unpack('>H', content[idx+2:idx+4])[0]
                print("0x{:2x} - tcp/{}".format((LOAD_ADDR + idx), port))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: {} firmware".format(sys.argv[0]))
        sys.exit(-1)
    hunt(sys.argv[1])
