#!/usr/bin/env python3
'''
It's Christmas time in eCOS world !

Author: Quentin Kaiser <quentin@ecos.wtf>
'''
import serial
import re
import time

def led_fun():
    with serial.Serial() as ser:
        ser.baudrate = 115200
        ser.port = '/dev/ttyUSB0'
        ser.open()
        ser.write(b"\n")
        ser.readline()

        ser.write(b"/Console/vendor/all_leds_off\n")
        ser.readline()
        ser.readline()
        for i in range(0, 10000):
            ser.write("/Console/vendor/led_on {}\n".format(i % 11).encode('utf-8'))
            ser.readline()
            ser.readline()
            time.sleep(0.1)
            ser.write("/Console/vendor/led_off {}\n".format(i % 11).encode('utf-8'))
            ser.readline()
            ser.readline()

if __name__ == "__main__":
    led_fun()
