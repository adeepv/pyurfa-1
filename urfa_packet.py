#coding=utf-8

""" URFA-packet class """

from urfa_const import *
from struct import unpack, pack
from pprint import pprint
import socket


class packet(object):
    """ packet - transport unit of URFA-protocol (7-lvl OSI) """

    def init(self, code=0, ver=U_VER, length=U_H_LEN, iter=0):
        """ initializing packet
        parameters:
            ver = U_VER - versiom of URFA-protocol
            length - length of packet in bytes
            iter - iterator of data in packet (need for reading multi-packet data)
        """
        self.code = code
        self.ver = ver
        self.length = length
        self.iter = iter
        self.attr = {}
        self.data = []

    def recv(self, sock):
        """ reacive packet from opened socket
        parameters:
            sock - opened socket-object
        returns:
            True - if code of attribute in recived packet don't contain error-codes
            False - if code of attribute in recived packet is error-code
        """
        eof = 0
        self.init()
        self.code = ord(sock.recv(1))
        self.ver = ord(sock.recv(1))
        self.length = unpack('!h', sock.recv(2))[0]
        curchar = U_H_LEN + 1
        while curchar < self.length:
            attr_code = unpack('h', sock.recv(2))[0]
            attr_len = unpack('!h', sock.recv(2))[0]
            attr_data = ''
            curchar += U_H_LEN
            if attr_len > U_H_LEN:
                attr_data = sock.recv(attr_len - U_H_LEN)
                curchar += attr_len - U_H_LEN
            if attr_code == U_CODE_DATA:
                self.data.append(attr_data)
            else:
                self.attr[attr_code] = dict({'data': attr_data, 'len': attr_len})
        if self.code == U_PKT_DATA:
            eof = self.get_attr(U_CODE_ATTR_EOF, U_TP_I)
        if eof and len(self.data) and self.get_data(U_TP_I) == U_CODE_ATTR_EOF:
            return False
        else:
            return True

    def send(self, sock):
        """ send packet through opened socket
        parameters:
            sock - opened socket-object
        """
        sock.send(chr(self.code))
        sock.send(chr(self.ver))
        sock.send(pack('!h', self.length))
        for attr in self.attr:
            sock.send(pack('h', attr))
            sock.send(pack('!h', self.attr[attr]['len']))
            sock.send(self.attr[attr]['data'])
        for data in self.data:
            sock.send(pack('h', U_CODE_DATA))
            sock.send(pack('!h', len(data) + U_H_LEN))
            if len(data):
                sock.send(data)

    def add_attr(self, code, value, type):
        """ adding attribute to packet
        parameters:
            code - code of attr. (from urfa_const)
            value - value of attr.
            type - type of attr. (from urfa_const)
        """
        attr_len = U_H_LEN
        if type == U_TP_S:
            attr_len = len(value) + U_H_LEN
        elif type == U_TP_I:
            attr_len = U_LEN_I
            value = pack('!l', value)
        self.attr[code] = dict({'data': value, 'len': attr_len})
        self.length += attr_len

    def get_attr(self, code, type):
        """ reading attribute of packet
        parameters:
            code - code of attr. (from urfa_const)
            type - type of attr. (from urfa_const)
        returns:
            data of attr. (int)- if packet contain attributes
            False - if packet don't contain attributes
        """
        if code in self.attr:
            if type == U_TP_I:
                return unpack('!L', self.attr[code]['data'])[0]
        else:
            return False

    def add_data(self, value, type):
        """ adding data to packet
        parameters:
            value - value of data
            type - type of data (from urfa_const)
        """
        data_len = 0
        if type == U_TP_S:
            data_len = len(value) + 4
        elif type == U_TP_I:
            data_len = U_LEN_I
            value = pack('!l', value)
        elif type == U_TP_L:
            data_len = U_LEN_L
            value = pack('!q', value)
        elif type == U_TP_D:
            data_len = U_LEN_D
            value = pack('!d', value)
        elif type == U_TP_IP:
            data_len = U_LEN_IP
            value = socket.inet_aton(value)
        self.data.append(value)
        self.length += data_len

    #        self.show()
    def get_data(self, type):
        """ reading data from packet
        parameters:
            type - type of data (from urfa_const)
        returns:
            data of packet
            None - if packet don't contain data
        """
        res = None
        if type == U_TP_S:
            res = self.data[self.iter]
        elif type == U_TP_I:
            res = unpack('!l', self.data[self.iter])[0]
        elif type == U_TP_L:
            res = unpack('!q', self.data[self.iter])[0]
        elif type == U_TP_D:
            res = unpack('!d', self.data[self.iter])[0]
        elif type == U_TP_IP:
            res = socket.inet_ntoa(self.data[self.iter])
        self.iter += 1
        return res

    def show(self):
        """ print the contents of packet """
        print self
        print "code: %s, ver: %s, len: %s, iter: %s" % (self.code, self.ver, self.length, self.iter, )
        print "attr:"
        pprint(self.attr)
        print "data:"
        pprint(self.data)
