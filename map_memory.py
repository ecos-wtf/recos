#!/usr/bin/env python3
import re
import sys
import struct

DEFAULT_LOAD_ADDRESS    = 0x80004000
HAL_ZERO_BSS_OFFSET     = 0x80004854

flirt = re.compile(b"\x3c\x04([\x00-\xFF][\x00-\xFF])\$\x84([\x00-\xFF][\x00-\xFF])\x3c\x05([\x00-\xFF][\x00-\xFF])\$\xa5([\x00-\xFF][\x00-\xFF])\x30\x86\x00\x03\x14\xc0\x00\x12")

fp =  open(sys.argv[1], 'rb')
fp.seek(HAL_ZERO_BSS_OFFSET - DEFAULT_LOAD_ADDRESS)
instruction = fp.read(24)
match = flirt.findall(instruction)
if match:
    a0_upper = struct.unpack(">H", match[0][0])[0]
    a0_lower = struct.unpack(">H", match[0][1])[0]
    a1_upper = struct.unpack(">H", match[0][2])[0]
    a1_lower = struct.unpack(">H", match[0][3])[0]
    bss_start = (a0_upper << 16) + a0_lower
    bss_end = (a1_upper << 16) + a1_lower
fp.close()

fp =  open(sys.argv[1], 'rb')
s = fp.read()
fp.close()

data_start_index = s.find(b"\x00\x00\x00\x00bcm0\x00\x00\x00\x00")
data_end_index = s.find(b"\x00" * 2000)
data_start = DEFAULT_LOAD_ADDRESS + data_start_index
data_end = DEFAULT_LOAD_ADDRESS + data_end_index

# we identify the string 'tStartup' in the data section
tstartup_index = s.find(b"tStartup\x00\x00\x00\x00")

# if we have a match, we search for an assembly pattern
if tstartup_index > -1:
    tstartup_addr = DEFAULT_LOAD_ADDRESS + tstartup_index

    # 807dd4b8 3c 07 80 fc     lui        a3,0x80fc
    # 807dd4bc 24 e7 03 34     addiu      a3,a3,0x334                 = "tStartup"
    pattern = b''.join([
        b"\x3c\x07",
        struct.pack(">H", tstartup_addr >> 16),
        b"\x24\xe7",
        struct.pack(">H", tstartup_addr - (tstartup_addr >> 16) * 0x10000)
        ]
    )
    instruction_index = s.find(pattern)
    instruction_addr = DEFAULT_LOAD_ADDRESS + instruction_index

    # we're looking for a call to cyg_thread_create(0x12,FUN_807dd4f8,0,"tStartup", stack_base, stack_size, handle, thread);
    # they use a custom calling convention
    # cyg_thread_create(a0, a1, a2, a3, t3, t1, t2, t0)
    # we're interested in register $t3 value which holds the stack_base address
    # given that tStartup is the first thread to run, stack_base is the actual start address of eCOS stack.

    '''
    3c 07 80 fc     lui        a3,0x80fc
    24 e7 03 34     addiu      a3=>s_tStartup_80fc0334,a3,0x334                 = "tStartup"
    3c 08 81 74     lui        t0,0x8174
    25 08 7c 48     addiu      t0,t0,0x7c48
    24 09 30 00     li         t1,0x3000
    3c 10 81 75     lui        s0,0x8175
    26 0a 3d 70     addiu      t2,s0,0x3d70
    3c 0b 81 75     lui        t3,0x8175
    0c 34 d1 0a     jal        cyg_thread_create                                undefined cyg_thread_create()
    25 6b 3c 48     _addiu     t3,t3,0x3c48
    '''


    lui_t3 = s[instruction_index+28:instruction_index+32]
    addui_t3 = s[instruction_index+36:instruction_index+40]
    if lui_t3[0:2] == b"\x3c\x0b" and addui_t3[0:2] == b"\x25\x6b":
        t3_upper = struct.unpack(">H", lui_t3[2:])[0]
        t3_lower = struct.unpack(">H", addui_t3[2:])[0]
        stack_start = (t3_upper << 16) + t3_lower
        stack_end = stack_start + 0x4000

print(".text start: 0x{:0x}".format(DEFAULT_LOAD_ADDRESS))
print(".text end: 0x{:0x}".format(data_start - 0x4))
print(".text length: 0x{:0x}".format(data_start - 0x4 - DEFAULT_LOAD_ADDRESS))

print(".data start: 0x{:0x}".format(data_start))
print(".data end: 0x{:0x}".format(data_end))
print(".data length: 0x{:0x}".format(data_end - data_start))

print(".bss_start: 0x{:0x}\n.bss_end: 0x{:0x}".format(bss_start, bss_end))
print("stack start: 0x{:0x}".format(stack_start))
print("stack end: 0x{:0x}".format(stack_end))
