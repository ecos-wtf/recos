#!/usr/bin/env python3
'''
Dump the virtual service routine table information from a live eCOS BFC device.
You must have a serial connection on /dev/ttyUSB0 to either a CM> or RG> shell.

Author: Quentin Kaiser <quentin@ecos.wtf>
'''
import serial
import re

VSR_ADDR = 0x80000300
VSR_NAMES = {
    0x800043ec: "__default_interrupt_vsr",
    0x80004bd8: "__default_exception_vsr",
    0x800042e0: "__default_exception_vsr"
}

CAUSES = [
    "Int\tInterrupt (hardware)",
    "Unk\tUnknown",
    "Unk\tUnknown",
    "Unk\tUnknown",
    "AdEL\tAddress Error exception (Load or instruction fetch)",
    "AdES\tAddress Error exception (Store)",
    "IBE\tInstruction fetch Buss Error",
    "DBE\tData load or store Buss Error",
    "Sys\tSyscall exception",
    "Bp\tBreakpoint exception",
    "RI\tReversed Instruction exception",
    "CpU\tCoprocessor Unimplemented",
    "Ov\tArithmetic Overflow exception",
    "Tr\tTrap",
    "FPE\tFloating Point Exception",
    "Unk\tUnknown"
]

def dump_vector_table():
    with serial.Serial() as ser:
        ser.baudrate = 115200
        ser.port = '/dev/ttyUSB0'
        ser.open()
        ser.write(b"\n")
        ser.readline()
        for i in range(0, 0x10):
            offset = VSR_ADDR + (i * 4)
            ser.write(
                "read_memory -n 4 0x{:0x}\n"\
                .format(offset)\
                .encode('utf-8')
            )
            ser.readline() # echo
            ser.readline() # newline
            output = ser.readline() # content
            ser.readline() # newline
            match = re.findall(b"[0-9-a-f]{8}: ([0-9-a-f ]{11})",output)
            address = int(match[0].replace(b" ", b"").decode('utf-8'), 16)
            if address in VSR_NAMES:
                name = VSR_NAMES[address]
            else:
                name = "UNKNOWN"
            print(
                    "{:<2}:0x{:0x}\t{:<5} 0x{:0x} {}".format(
                    i,
                    offset,
                    name,
                    address,
                    CAUSES[i]
                )
            )

if __name__ == "__main__":
    dump_vector_table()
