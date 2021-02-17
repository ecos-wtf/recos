# ReCOS

Reverse engineering resources for the eCOS platform. Mostly focused on Broadcom eCOS platform at the moment.

## Broadcom eCOS Device Static Analysis

### Device Memory Mapper

Identify patterns in firmware code to derive the memory segments (.text, .data, .bss, stack) of a given device. You can use that information to define memory mappings in your SRE tool of choice.

```
./map_memory.py firmware.decompressed.bin
.text start: 0x80004000
.text end: 0x80e20ae0
.text length: 0xe1cae0
.data start: 0x80e20ae4
.data end: 0x81011a00
.data length: 0x1f0f1c
.bss_start: 0x816168c8
.bss_end: 0x81b52570
stack start: 0x81753c48
stack end: 0x81757c48
```

## Broadcom eCOS Device Dynamic Analysis

### Virtual Vector Table Dumper

Dump the virtual vector table information from a live eCOS BFC device over serial.

```
./dump_vector_table.py
0x80000400	Virtual Vector Table Version            0x80015
0x80000404	Interrupt Table                         0x80d97fb8 (nop)
0x80000408	Exception Table                         0x80d97fb8 (nop)
0x8000040c	Debug Vector                            0x80d97fb8 (nop)
0x80000410	Kill Vector                             0x80d97f80
0x80000414	Console I/O Procedure Table             0x81967908
0x80000418	Debug I/O Procedure Table               0x81967908
0x8000041c	Flush Data Cache                        0x80d98308
0x80000420	Flush Instruction Cache                 0x80d982f0
0x80000424	CPU Data                                0x80d97fb8 (nop)
0x80000428	Board Data                              0x80d97fb8 (nop)
0x8000042c	System Information                      0x80d97fb8 (nop)
0x80000430	Set Debug Communication Channel         0x80d97fc0
0x80000434	Set Console Communication Channel       0x80d98230
0x80000438	Set Serial Baud Rate                    0x0
0x8000043c	Debug System Call                       0x80d97fb8 (nop)
0x80000440	Reset                                   0x80d97f68
0x80000444	Console Interrupt Flag                  0x0
0x80000448	Microsecond delay                       0x80d97ecc
0x8000044c	Debug Data                              0x812b2894
0x80000450	Flash ROM Configuration                 0x80d97fb8 (nop)
0x80000454	RESERVED                                0x80d97fb8 (nop)
0x80000458	RESERVED                                0x80d97fb8 (nop)
0x8000045c	RESERVED                                0x80d97fb8 (nop)
0x80000460	RESERVED                                0x80d97fb8 (nop)
0x80000464	RESERVED                                0x80d97fb8 (nop)
0x80000468	RESERVED                                0x80d97fb8 (nop)
0x8000046c	RESERVED                                0x80d97fb8 (nop)
0x80000470	RESERVED                                0x80d97fb8 (nop)
0x80000474	RESERVED                                0x80d97fb8 (nop)
0x80000478	RESERVED                                0x80d97fb8 (nop)
0x8000047c	RESERVED                                0x80d97fb8 (nop)
0x80000480	RESERVED                                0x80d97fb8 (nop)
0x80000484	RESERVED                                0x80d97fb8 (nop)
0x80000488	RESERVED                                0x80d97fb8 (nop)
0x8000048c	Install breakpoint                      0x80d97fb8 (nop)
0x80000490	RESERVED                                0x80d97fb8 (nop)
0x80000494	RESERVED                                0x80d97fb8 (nop)
0x80000498	RESERVED                                0x80d97fb8 (nop)
0x8000049c	RESERVED                                0x80d97fb8 (nop)
0x800004a0	RESERVED                                0x80d97fb8 (nop)
0x800004a4	RESERVED                                0x80d97fb8 (nop)
0x800004a8	RESERVED                                0x80d97fb8 (nop)
0x800004ac	RESERVED                                0x80d97fb8 (nop)
0x800004b0	RESERVED                                0x80d97fb8 (nop)
0x800004b4	RESERVED                                0x80d97fb8 (nop)
0x800004b8	RESERVED                                0x80d97fb8 (nop)
0x800004bc	RESERVED                                0x80d97fb8 (nop)
0x800004c0	RESERVED                                0x80d97fb8 (nop)
0x800004c4	RESERVED                                0x80d97fb8 (nop)
0x800004c8	RESERVED                                0x80d97fb8 (nop)
0x800004cc	RESERVED                                0x80d97fb8 (nop)
0x800004d0	RESERVED                                0x80d97fb8 (nop)
0x800004d4	RESERVED                                0x80d97fb8 (nop)
0x800004d8	RESERVED                                0x80d97fb8 (nop)
0x800004dc	RESERVED                                0x80d97fb8 (nop)
0x800004e0	RESERVED                                0x80d97fb8 (nop)
0x800004e4	RESERVED                                0x80d97fb8 (nop)
0x800004e8	RESERVED                                0x80d97fb8 (nop)
0x800004ec	RESERVED                                0x80d97fb8 (nop)
0x800004f0	RESERVED                                0x80d97fb8 (nop)
0x800004f4	RESERVED                                0x80d97fb8 (nop)
0x800004f8	RESERVED                                0x80d97fb8 (nop)
0x800004fc	Virtual Vector Table                    0x80d97fb8 (nop)
```

### Virtual Service Routine Table Dumper

Dump the virtual service routine table information from a live eCOS BFC device over serial.

```
./dump_vsr.py
0 :0x80000300	__default_interrupt_vsr 0x800043ec Int	Interrupt (hardware)
1 :0x80000304	__default_exception_vsr 0x80004bd8 Unk	Unknown
2 :0x80000308	__default_exception_vsr 0x80004bd8 Unk	Unknown
3 :0x8000030c	__default_exception_vsr 0x80004bd8 Unk	Unknown
4 :0x80000310	__default_exception_vsr 0x80004bd8 AdEL	Address Error exception (Load or instruction fetch)
5 :0x80000314	__default_exception_vsr 0x80004bd8 AdES	Address Error exception (Store)
6 :0x80000318	__default_exception_vsr 0x80004bd8 IBE	Instruction fetch Buss Error
7 :0x8000031c	__default_exception_vsr 0x80004bd8 DBE	Data load or store Buss Error
8 :0x80000320	__default_exception_vsr 0x80004bd8 Sys	Syscall exception
9 :0x80000324	__default_exception_vsr 0x80004bd8 Bp	Breakpoint exception
10:0x80000328	__default_exception_vsr 0x80004bd8 RI	Reversed Instruction exception
11:0x8000032c	__default_exception_vsr 0x80004bd8 CpU	Coprocessor Unimplemented
12:0x80000330	__default_exception_vsr 0x80004bd8 Ov	Arithmetic Overflow exception
13:0x80000334	__default_exception_vsr 0x80004bd8 Tr	Trap
14:0x80000338	__default_exception_vsr 0x80004bd8 FPE	Floating Point Exception
15:0x8000033c	__default_exception_vsr 0x80004bd8 Unk	Unknown
```

### Heap Dumper

Dump the whole heap region from live eCOS BFC device. I'm aware the content is
changing as I'm dumping its content but it was useful to understand the heap
allocator so I keep it here for historical reasons.

You must have a serial connection on /dev/ttyUSB0 to either a CM> or RG> shell.

```
./dump_heap.py
[+] Getting heap region addresses.
[+] Heap start: 0x81b52570
[+] Heap end: 0x87f01ff4
[+] Dumping region to heap.dump
[+] Reading memory from 0x81b52570
```

## Broadcom eCOS Bootloader Static Analysis

### Functions Demangling

Analyze a binary looking for function name logging strings and cross-reference them to their actual function location.
 
Useful to identify functions to instrument to interact with SPI or NAND flash (e.g. NandFlashRead, NandFlashWrite, SpiFlashRead, SpiFlashWrite).

These functions offsets are required if you plan on writing a device profile for [bcm2-utils](https://github.com/jclehner/bcm2-utils). Note that some bootloaders are stripped of these strings, but the results can be used to create a function database (think FLIRT or FunctionID) that you can apply to them.

```
./ecos_bootloader_analysis.py bootloader.clean.bin
[+] Binary loaded. Launching analysis.
[+] Looking through strings ...
[+] 28 potential function names identified
Identified function                     Name                Offset
--------------------------------------------------------------------------------
ETHrxData                               fcn.83f85cd0        (0x83F85CD0)
ETHtxData                               fcn.83f85dc8        (0x83F85DC8)
NandFlashCopyBlock                      fcn.83f841f0        (0x83F841F0)
NandFlashCopyPage                       fcn.83f839f8        (0x83F839F8)
NandFlashEraseBlock                     fcn.83f83830        (0x83F83830)
NandFlashEraseNextGoodBlock             fcn.83f8395c        (0x83F8395C)
NandFlashMarkBadBlock                   fcn.83f836e8        (0x83F836E8)
NandFlashRead                           fcn.83f83e9c        (0x83F83E9C)
NandFlashRewriteBlock                   fcn.83f842ec        (0x83F842EC)
NandFlashWaitReady                      fcn.83f83164        (0x83F83164)
NandFlashWrite                          fcn.83f834fc        (0x83F834FC)
NandFlashWriteBuf                       NandFlashWrite      (0x83F834FC)
PinMuxGet                               fcn.83f84ca0        (0x83F84CA0)
PinMuxSel                               fcn.83f84c20        (0x83F84C20)
PmcCommandIf                            fcn.83f8485c        (0x83F8485C)
PowerDeviceOff                          fcn.83f845c4        (0x83F845C4)
PowerDeviceOn                           fcn.83f84680        (0x83F84680)
ReadBPCMReg                             fcn.83f844cc        (0x83F844CC)
SpiFlashCmdAddr                         fcn.83f81038        (0x83F81038)
SpiFlashWrite                           fcn.83f81148        (0x83F81148)
SwitchReadInt                           fcn.83f82ca4        (0x83F82CA4)
TransmitBurst                           fcn.83f86158        (0x83F86158)
ValidateFlashMap                        fcn.83f82028        (0x83F82028)
WriteBPCMReg                            fcn.83f843f0        (0x83F843F0)
```

## eCOS Firmware Static Analysis

### eCOS Standard Library FunctionID Generation

You can generate shared objects of eCOS standard library within a Vagrant virtual machine (see fidb-vm) and automagically generated a FunctionID database file out of it. **I strongly recommend you simply download the FIDB files that I made available through that repo though**. They work for eCOS 1.0, 2.0, and parts of 3.0. The documentation below is only helpful if you want to reproduce the build process.

```
vagrant up
```

Once they are generated, you can pull them off:

```
scp -r -i .vagrant/machines/default/libvirt/private_key vagrant@192.168.121.102:'/tmp/ecoslibs'
```

You have to run the sortlib script to make the directory structure right for the Ghidra auto-analyzer:

```
cd ecoslibs
../sortlib.py
```

This will put everything in `/tmp/sorted`. Next, you can run the FIDB generator:

```
auto_fidb.sh
```

### eCOS Broadcom Function Auto-Renaming (Ghidra)

Simply copy `BcmDebugLogsRenameFunctions.java` into your ghidra_scripts directory and it will appear in your Ghidra scripts. The script relies on the existence of specific functions, named `debug_logger`. The script will faile if you did not identify those first, and they vary from firmware to firmware (but once you're onto them, you'll auto-rename thousands of functions in one go).

### eCOS Broadcom C++ vtable Auto-Renaming (Ghidra)

Simply copy `BcmRenameLabelVTable.java` into your ghidra_scripts directory and it will appear in your Ghidra scripts. The script will have zero effect if you did not auto-rename the functions first as it will look for patterns of C++ function names (with '::' in it). 

## eCOS Firmware Dynamic Analysis

### GDB Stubs in Production Firmware

This is an ongoing endeavour. The plan is to write to memory a piece of code that will launch a high priority thread exposing a GDB server, with breakpoint and fault handling capabilities.

## Exploit Writing

### Shellcode Generation

See the [ecoshell](https://github.com/ecos-wtf/ecoshell) project.

### AF\_INET Hunter

Search firmware file for a pattern starting with \x00\x02 so that it can be
re-used by ROP chains in need of an AF_INET value for their sockaddr_in structures.

The script will print the corresponding TCP port that the device will try connecting
to if a specific address is used to construct the sockaddr_in struct.

## Miscellaneous

### LED Fun

It's Christmas time in eCOS world ! The `led_fun.py` is a sample script to make all led blink, useful if you want to demonstrate code execution.


## Resources

- [https://github.com/jclehner/bcm2-utils](https://github.com/jclehner/bcm2-utils) - OG tool that helped kickstart all of this.
- [https://github.com/jclehner/bcm2-dumps](https://github.com/jclehner/bcm2-dumps) - Firmware images for BCM33XX modems, useful if you want to get your hands dirty without having access to an actual device.
