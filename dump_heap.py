#!/usr/bin/env python3
'''
Dump the whole heap region from live eCOS BFC device. I'm aware the content is
moving as I'm dumping its content but it was useful to understand the heap
allocator so I keep it here for historical reasons.

You must have a serial connection on /dev/ttyUSB0 to either a CM> or RG> shell.

Author: Quentin Kaiser <quentin@ecos.wtf>
'''
import struct
import re
import serial
import telnetlib

# can be either CM> or RG>
PROMPT = b"CM>"

def read_memory(ser, offset, size):
    ser.write("read_memory -n {} 0x{:0x}\n".format(size, offset).encode('utf-8'))
    ser.readline() # echo
    ser.readline() # newline
    ser.write(b"\n")
    content = b""
    line = b""
    while line != b"\r\n":
        line = ser.readline() # content
        ser.readline() # newline
        match = re.findall(r"([a-f0-9]{8}): ([a-f0-9 ]{11})  ([a-f0-9 ]{11})  ([a-f0-9 ]{11})  ([a-f0-9 ]{11})", line.decode('utf-8'))
        if match:
            for i in range(1, 4):
                addr = int(match[0][i].replace(" ", ""), 16)
                content += struct.pack(">I", addr)
    return content

def get_heap_region(ser):

    content = b""
    ser.write(b"/HeapManager/stats\n")
    ser.readline() # echo
    ser.readline() # newline
    ser.write(b"\n")
    while PROMPT not in content:
        content += ser.readline() # content
        content += ser.readline() # newline
    start, end = re.findall(r"Region\[0\] start = (0x[0-9a-f]{8})\r\n\t  Region\[0\] end = (0x[0-9a-f]{8})", content.decode('utf-8'))[0]
    return int(start, 16), int(end, 16)

def dump_heap(mode="serial"):

    heap = b""
    if mode == "telnet":
        dump_vector_table_telnet()
    with serial.Serial() as ser:
        ser.baudrate = 115200
        ser.port = '/dev/ttyUSB0'
        ser.open()
        ser.write(b"\n")
        ser.readline()
        print("[+] Getting heap region addresses.")
        start, end = get_heap_region(ser)
        print("[+] Heap start: 0x{:2x}".format(start))
        print("[+] Heap end: 0x{:2x}".format(end))
        print("[+] Dumping region to heap.dump")
        size = int(end - start)
        chunks = int(size / 0x4000)
        page_size = 0x4000

        for i in range(0, chunks):
            offset = start + (i * page_size)
            print("[+] Reading memory from 0x{:2x}".format(offset))
            heap += read_memory(ser, offset, page_size)

    with open("heap.dump", "wb") as f:
        f.write(heap)

if __name__ == "__main__":
    dump_heap()
