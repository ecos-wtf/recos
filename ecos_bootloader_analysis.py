#!/usr/bin/env python3
'''
eCos bootloader analysis script.

Analyze a binary looking for function name logging strings and cross-reference
them to their actual function location.

Useful to identify functions to instrument to interact with SPI or NAND flash
(e.g. NandFlashRead, NandFlashWrite, SpiFlashRead, SpiFlashWrite).

Author: Quentin Kaiser <quentin@ecos.wtf>
'''
import sys
import json
import re
import r2pipe


def analyze(filename, base_addr=0x83f80000, arch='mips', bits=32, big_endian='true'):
    '''
    Load filename with radare2 and performs analysis. Results are printed out
    as tabular data in stdout.

    Args:
        filename(str): bootloader's filename
        base_addr(int): bootloader's load address
        arch(str): bootloader's architecture
        bits(int): bootloader address size
        big_endian(bool): bootloader endianness

    Returns:
        None
    '''
    r2session = r2pipe.open(
        filename,
        flags=[
            '-2',
            '-a', arch,
            '-b', '{}'.format(bits),
            '-m', '0x{0:02x}'.format(base_addr),
            '-e', 'cfg.bigendian={}'.format(big_endian)
        ]
    )

    print("[+] Binary loaded. Launching analysis.")
    r2session.cmd("aaaa")
    print("[+] Looking through strings ...")
    raw_data = r2session.cmd("izzj")

    # first we get all strings from the binary and identify function
    # names with our regular expression pattern
    func_names = set()
    for line in json.loads(raw_data):
        if re.match(r"[A-Z][A-z]{8,30}:", line['string']):
            func_name = line['string'].split(':')[0]
            func_names.add(func_name)

        if re.match(r"[A-Z][A-z]{8,30} [E|e]rror:", line['string']):
            func_name = line['string'].split(' ')[0]
            func_names.add(func_name)

    print("[+] {} potential function names identified".format(len(func_names)))
    # for each function name, we identify its location in the binary
    # and xref it to the function where it is mentioned. We then
    # rename the function
    print("{0:40s}{1:20s}{2:20s}".format("Identified function", "Name", "Offset"))
    print("-"*80)
    for func_name in sorted(func_names):
        func_name_refs = json.loads(r2session.cmd("/j {}".format(func_name)))
        for func_name_ref in func_name_refs:
            func_xrefs = json.loads(r2session.cmd("axtj 0x{0:02x}".format(func_name_ref["offset"])))
            if func_xrefs:
                print("{0:40s}{1:20s}(0x{2:02X})".format(
                    func_name, func_xrefs[0]["fcn_name"], func_xrefs[0]['fcn_addr']))
                r2session.cmd("afn {} {}".format(func_name, func_xrefs[0]["fcn_name"]))
                break

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: {} bootloader".format(sys.argv[0]))
        sys.exit(-1)
    analyze(sys.argv[1])
