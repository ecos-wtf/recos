#!/usr/bin/env python3
'''
Dump the virtual vector table information from a live eCOS BFC device.
You must have a serial connection on /dev/ttyUSB0 to either a CM> or RG> shell.

Author: Quentin Kaiser <quentin@ecos.wtf>
'''
import re
import serial
import telnetlib


VVT_ADDR = 0x80000400
VVT_NAMES = [
    "Virtual Vector Table Version",
    "Interrupt Table",
    "Exception Table",
    "Debug Vector",
    "Kill Vector",
    "Console I/O Procedure Table",
    "Debug I/O Procedure Table",
    "Flush Data Cache",
    "Flush Instruction Cache",
    "CPU Data",
    "Board Data",
    "System Information",
    "Set Debug Communication Channel",
    "Set Console Communication Channel",
    "Set Serial Baud Rate",
    "Debug System Call",
    "Reset",
    "Console Interrupt Flag",
    "Microsecond delay",
    "Debug Data",
    "Flash ROM Configuration",
]

VVT_NAMES += ["RESERVED"] * 44
VVT_NAMES[35] = "Install breakpoint"
VVT_NAMES[63] = "Virtual Vector Table"

def read_memory(ser, offset):
    ser.write("read_memory -n 4 0x{:0x}\n".format(offset).encode('utf-8'))
    ser.readline() # echo
    ser.readline() # newline
    output = ser.readline() # content
    ser.readline() # newline
    return output

def is_nop_service(asm):
    # jr         ra
    # _clear     v0
    return True if asm == "03e0000800001021" else False


def dump_vector_table(mode="serial"):

    if mode == "telnet":
        return dump_vector_table_telnet()
    with serial.Serial() as ser:
        ser.baudrate = 115200
        ser.port = '/dev/ttyUSB0'
        ser.open()
        ser.write(b"\n")
        ser.readline()
        for i in range(0, 0x40):
            offset = VVT_ADDR + (i * 4)
            output = read_memory(ser, offset)
            match = re.findall(b"[0-9-a-f]{8}: ([0-9-a-f ]{11})",output)
            addr = int(match[0].replace(b" ", b"").decode('utf-8'), 16)
            if addr > 0x80004000:
                ser.write("read_memory -n 8 0x{:0x}\n".format(addr).encode('ascii'))
                ser.readline() # echo
                ser.readline() # newline
                output = ser.readline() # content
                ser.readline() # newline
                match = re.findall(b"[0-9-a-f]{8}: ([0-9-a-f ]{24})",output)
                asm = match[0].replace(b" ", b"").decode('utf-8')
            else:
                asm = ""
            print(
                "0x{:0x}\t{:<40}0x{:0x} {}".format(
                    offset,
                    VVT_NAMES[i],
                    addr,
                    "(nop)" if is_nop_service(asm) else ""
                )
            )

if __name__ == "__main__":
    dump_vector_table()
