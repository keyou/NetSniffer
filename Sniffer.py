import socket
import struct
import thread
import threading
import time
import os
import ctypes
import inspect
import sys

from EasiNet.Protocol.Common_pb2 import *
from EasiNet.Protocol.Control_pb2 import *
from EasiNet.Protocol.Operation_pb2 import *

import binascii

HeadLength = 9
TailLength = 1

Head = None
HeadCache = ''
Body = None
BodyCache = ''
Tail = None
TailCache = ''

allClass = inspect.getmembers(sys.modules[__name__], inspect.isclass)
print(allClass)
commands = []
for name, type in allClass:
    if name.endswith('Command'):
        commands.append((name, type))

class EasiCommand(object):
    def __init__(self):
        self.NetCommand = NetCommand()
        self.Command = None

    def __str__(self):
        return "%s \n%s" % (self.NetCommand , self.Command)

    @classmethod
    def Parse(cls, data):
        easiCommand = EasiCommand()
        easiCommand.NetCommand.ParseFromString(data)
        commandTypeStr = CommandEnum.Name(easiCommand.NetCommand.CommandType)+"Command"
        commandType = globals()[commandTypeStr]
        if commandType is None:
            return
        easiCommand.Command = commandType()
        easiCommand.Command.ParseFromString(easiCommand.NetCommand.CommandData)
        return easiCommand

class CommandHead(ctypes.BigEndianStructure):
    _fields_ = [
        ('flag', ctypes.c_ubyte),
        ('length', ctypes.c_int32),
        ('mainCmd', ctypes.c_ubyte),
        ('subCmd', ctypes.c_ubyte),
        ('reserves', ctypes.c_ubyte * 2)]
    _pack_ = 1

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass

    def __str__(self):
        return 'length: %d, main: %d, sub:%d' % (self.length, self.mainCmd, self.subCmd)

    @classmethod
    def Parse(cls,data):
        return CommandHead(data)

def parseHead(buf,offset,length):
    global Head,HeadCache,Body,BodyCache,Tail,TailCache
    writelength = min(length, HeadLength - len(HeadCache))
    HeadCache += buf[offset:offset+writelength]
    if len(HeadCache) == HeadLength:
        Head = CommandHead.Parse(HeadCache)
        print Head
        Body = None
        BodyCache = ''
    return writelength

def parseBody(buf,offset,length):
    global Head,HeadCache,Body,BodyCache,Tail,TailCache
    writelength = min(length, Head.length - len(BodyCache))
    BodyCache += buf[offset:offset+writelength]
    if len(BodyCache) == Head.length:
        Body = EasiCommand.Parse(BodyCache)
        Tail = None
        TailCache = ''
    return writelength

def parseTail(buf,offset,length):
    global Head,HeadCache,Body,BodyCache,Tail,TailCache
    writelength = min(length, TailLength - len(TailCache))
    TailCache += buf[offset:offset+writelength]
    if len(TailCache) == TailLength:
        Tail = TailCache
        print '----------------------------------------------------------------------------'
        print Body
        Head = None
        HeadCache = ''
    return writelength

def processData(buf):
    #print buf
    length = len(buf)
    offset = 0
    while length > 0:
        if Head is None:
            writelength = parseHead(buf,offset,length)
            offset += writelength
            length -= writelength
        elif Body is None:
            writelength = parseBody(buf,offset,length)
            offset += writelength
            length -= writelength
        else:
            writelength = parseTail(buf,offset,length)
            offset += writelength
            length -= writelength


def get_packet():
    HOST = socket.gethostbyname(socket.gethostname())
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    HOST = '127.0.0.1'  # '169.254.110.192' #'14.23.184.237'
    s.bind((HOST, 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    while True:
        buf = s.recvfrom(65565)[0]
        # print 'buf[0]'+str(len(buf[0]))+": "+ str(binascii.b2a_hex(buf[0]))
        # print 'buf[0]'+str(len(buf)-40)+": "+ str(buf[40:])
        port = struct.unpack('HH', buf[20:24])

        src_ip = "%d.%d.%d.%d" % struct.unpack('BBBB', buf[12:16])
        dest_ip = "%d.%d.%d.%d" % struct.unpack('BBBB', buf[16:20])
        src_port = socket.htons(port[0])
        dest_port = socket.htons(port[1])
        if src_port != 12021 and dest_port != 12021:  # or (ord(buf[33]) & 0b00001000 == 0):
            continue

        data_len = len(buf)
        key = "%s:%d - %s:%d - %d - %s" % (src_ip, src_port, dest_ip, dest_port, data_len - 40, str(buf[40:]))
        # print key
        processData(buf[40:])

get_packet()
os.exit()

