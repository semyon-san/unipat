# unipat
 Tool to assist in program exploitation process
 
```
usage: unipat.py [-h] [--badchars LENGTH] [--pattern LENGTH] [--offset LENGTH]
                 [--lendian ADDRESS] [--toint HEX] [-b BADCHARS] [-s CHAR]
                 [-e ADDRESS] [-r]

unipat v1.9 by s3my0n

optional arguments:
  -h, --help         show this help message and exit

Functions:
  --badchars LENGTH  Generate a list of chars starting from "\x01"
  --pattern LENGTH   Generate a non-repeating list of alphanumeric chars
  --offset LENGTH    Calculate the offset in the pattern of a given length.
                     Use with -e
  --lendian ADDRESS  Convert hex address (ex: 0xbffff7e5) to little endian
                     format
  --toint HEX        Convert hexadecimal to integer

For --badchars:
  -b BADCHARS        Exclude badchars. Example: "\xff\xcc\x0b\x00"
  -s CHAR            Character to start from. Example: "\x00"

For --offset:
  -e ADDRESS         Find offset at this address (use with --offset <num>)

For all:
  -r                 Output in raw format
```
