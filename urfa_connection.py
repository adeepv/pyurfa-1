#coding=utf-8

"""
    URFA-connection class
"""

from urfa_const import *
from urfa_packet import packet
import socket
import hashlib
import ssl
import os


class connection(object):
    """
    urfa-connection
    """

    def urfa_login(self):
        """
        handshake and login
        """
        self.sck.connect((self.addr, self.port))
        self.pck.recv(self.sck)
        session_id = self.pck.attr[U_CODE_ATTR_SID]['data']
        auth_hash_digest = hashlib.new('md5')
        auth_hash_digest.update(session_id)
        auth_hash_digest.update(self.passwd)
        auth_hash = auth_hash_digest.digest()
        self.pck.init(code=U_PKT_REQ)
        if self.admin:
            login_type = U_LGN_SYS
            ssl_type = U_SSLT_RSACRT
        else:
            login_type = U_LGN_USR
            ssl_type = U_SSLT_SSL3
        self.pck.add_attr(U_CODE_ATTR_LGN_T, login_type, U_TP_I)
        self.pck.add_attr(U_CODE_ATTR_LGN, self.login, U_TP_S)
        self.pck.add_attr(U_CODE_ATTR_DGS, session_id, U_TP_S)
        self.pck.add_attr(U_CODE_ATTR_HSH, auth_hash, U_TP_S)
        self.pck.add_attr(U_CODE_ATTR_SSL, ssl_type, U_TP_I)
        self.pck.send(self.sck)
        self.pck.recv(self.sck)
        if self.pck.code == U_PKT_ACCEPT:
            if self.admin:
                self.sck = ssl.wrap_socket(self.sck, certfile=self.crt_file, ssl_version=ssl.PROTOCOL_SSLv3)
            else:
                self.sck = ssl.wrap_socket(self.sck, ciphers='ADH-RC4-MD5', ssl_version=ssl.PROTOCOL_SSLv3)

    def urfa_call(self, fn_code):
        """
        call urfa-function
        """
        self.pck.init(code=U_PKT_CALL)
        self.pck.add_attr(U_CODE_ATTR_FN, fn_code, U_TP_I)
        self.pck.send(self.sck)
        return self.pck.recv(self.sck)

    def __init__(self, addr, port, login, passwd, admin=False,
                 crt_file=os.path.join(os.path.dirname(__file__), 'urf_admin.crt').replace('\\', '/'),):
        """
        init urfa-connection class
        """
        self.sck = socket.socket()
#        self.sck.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.pck = packet()
        self.addr = addr
        self.port = port
        self.login = login
        self.passwd = passwd
        self.admin = admin
        self.crt_file = crt_file
        self.urfa_login()

    def __del__(self):
        """
        close the socket to server in destroy
        """
        self.sck.close()
