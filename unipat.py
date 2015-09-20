#!/usr/bin/python

#Name:    unipat.py
#Version: 1.9
#Author:  s3my0n

#########################################################################
# unipat is a tool to assist in program exploitation process. It can    #
# generate (in a programming string or raw format) a list of one byte   #
# hexadecimal values and filter out bad input characters. Also it can   #
# generate unique alphanumeric characters and thus find offset size     #
# to the return address.                                                #
# Finally it can convert hexadecimal addresses to little endian format, #
# and print them out in either programming string or raw format.        #
#                                                                       #
# Copyright (C) 2015 s3my0n                                             #
#                                                                       #
# This program is free software: you can redistribute it and/or modify  #
# it under the terms of the GNU General Public License as published by  #
# the Free Software Foundation, either version 3 of the License, or     #
# any later version.                                                    #
#                                                                       #
# This program is distributed in the hope that it will be useful,       #
# but WITHOUT ANY WARRANTY; without even the implied warranty of        #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         #
# GNU General Public License for more details.                          #
#                                                                       #
# You should have received a copy of the GNU General Public License     #
# along with this program.  If not, see <http://www.gnu.org/licenses/>. #
#########################################################################

import argparse
import binascii
import struct
import sys
import re

__author__  = 's3my0n'
__version__ = 1.9

def badchars(length, start=0, bad=''):
    if (length < 1 or length > 255):
        raise ValueError('length should be between 1 and 255 inclusive')
    start = ord(start)
    if start > length:
        raise ValueError('start cannot be greater than length')
    chars = [i for i in range(start, length+1) if i not in bad] 
    return struct.pack('%dB'%len(chars), *chars)

def pattern(length):
    if length < 1 or length > 20280:
        raise ValueError('length should be between 1 and 20280 inclusive')
        
    chars = []
    upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    lower = 'abcdefghijklmnopqrstuvwxyz'
    digits = '0123456789'
    count = 0
    for i in upper:
        for j in lower:
            for k in digits:
                chars.append(''.join((i, j, k)))
                count += 3
                if (count >= length):
                    return ''.join(chars)[:count-(count-length)]

def pattern_offset(length, eip):
    eip = ''.join([chr(i) for i in raw_hex(eip)])[::-1]
    haystack = pattern(length)
    try:
        return haystack.index(eip)
    except ValueError:
        raise ValueError('{} not in the pattern of length {}'.format(eip, length))

def lendian(address):
    return address[::-1]

def toint(hex):
    return int(hex, 16)

def raw_hex(hex):
    hex = hex.lstrip('0x')
    if len(hex) % 2 != 0:
        hex = '0'+hex
    return binascii.unhexlify(hex)

def raw_hex_string(hex_string):
    return binascii.unhexlify(''.join(hex_string.split('\\x'))) 

def hex_escape(raw):
    return ''.join(['\\x%02x' % i for i in raw])

def print_raw(raw):
    sys.stdout.buffer.write(raw)

##### ARGUMENT PARSING STUFF START #####

def check_int(value):
    try:
        return int(value)
    except ValueError:
        raise argparse.ArgumentTypeError('Should be an integer')

def check_badchars(value):
    value = check_int(value)
    if value < 1 or value > 255:
         raise argparse.ArgumentTypeError('Should be between 1 and 255 inclusive')
    return value

def check_pattern(value):
    value = check_int(value)
    if value < 1:
         raise argparse.ArgumentTypeError('Should be positive')
    return value

def check_offset(value):
    value = check_int(value)
    if value < 1:
         raise argparse.ArgumentTypeError('Should be positive')
    return value

def check_hex_string(value):
    value = value.lower()
    if value and not re.match(r"^(\\x[\da-f]{2})+$", value):
        raise argparse.ArgumentTypeError('Invalid hex string')
    return value

def check_hex(value):
    value = value.lower()
    if not re.match(r"^(0x)?[0-9a-f]+$", value):
        raise argparse.ArgumentTypeError('Invalid hex number')
    return value

def parse_args(argv):
    args = {}

    parser = argparse.ArgumentParser(description='unipat v{} by {}'.format(__version__, __author__))

    functions = parser.add_argument_group('Functions')
    functions.add_argument('--badchars', type=check_badchars, metavar='LENGTH', help='Generate a list of chars starting from "\\x01"')
    functions.add_argument('--pattern', type=check_pattern, metavar='LENGTH', help='Generate a non-repeating list of alphanumeric chars')
    functions.add_argument('--offset', type=check_offset, metavar='LENGTH', help='Calculate the offset in the pattern of a given length. Use with -e')
    functions.add_argument('--lendian', type=check_hex, metavar='ADDRESS', help='Convert hex address (ex: 0xbffff7e5) to little endian format')
    functions.add_argument('--toint', type=check_hex, metavar='HEX', help='Convert hexadecimal to integer')

    badchars = parser.add_argument_group('For --badchars')
    badchars.add_argument('-b', type=check_hex_string, default='', metavar='BADCHARS', help='Exclude badchars. Example: "\\xff\\xcc\\x0b\\x00"')
    badchars.add_argument('-s', type=check_hex_string, default='\\x01', metavar='CHAR', help='Character to start from. Example "\\x00"')

    offset = parser.add_argument_group('For --offset')
    offset.add_argument('-e', type=check_hex, metavar='ADDRESS', help='Find offset at this address (use with --offset <num>)')

    general = parser.add_argument_group('For all')
    general.add_argument('-r', action='store_true', default=False, help='Output in raw format')

    args = vars(parser.parse_args(argv))

    return args

##### ARGUMENT PARSING STUFF END #####

if __name__ == '__main__':
    args = parse_args(sys.argv[1:])

    try:
        if args['badchars']:
            result = badchars(args['badchars'], start=raw_hex_string(args['s']), bad=raw_hex_string(args['b']))
            if args['r']:
                print_raw(result)
            else:
                print(hex_escape(result))
        elif args['pattern']:
            result = pattern(args['pattern'])
            if args['r']:
                print(result, end='')
            else:
                print(result)
        elif args['offset']:
            if not args['e']:
                print('[-] Need option "-e" for "--offset"')
                sys.exit(1)
            result = pattern_offset(args['offset'], args['e'])
            if args['r']:
                print(result, end='')
            else:
                print(result)
        elif args['lendian']:
            result = lendian(raw_hex(args['lendian']))
            if args['r']:
                print_raw(result)
            else:
                print(hex_escape(result))
        elif args['toint']:
            result = toint(args['toint'])
            if args['r']:
                print(result, end='')
            else:
                print(result)
        else:
            print('Use "-h" or "--help" to see available options')

    except ValueError as e:
        print('[!] Error: {}'.format(e))
        sys.exit(1)
