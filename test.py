from urfa import urfa_client
import socket, ssl, pprint
import os
import sys

def resource_path(relative):
    return os.path.join(getattr(sys, '_MEIPASS', os.path.abspath(".")),
                        relative)
cert_path = resource_path('admin.crt')

bill = urfa_client('bill.nester.ru', 11758, 'init', 'init02Nit87',admin=True,crt_file=cert_path)
#bill = urfa_client('bill.nester.ru', 11758, 'admin', 'S5Hx98', admin=True,crt_file= 'admin.crt')
exit()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


ssl_sock = ssl.wrap_socket(s,ca_certs=cert_path,cert_reqs=ssl.CERT_REQUIRED)

ssl_sock.connect(('www.verisign.com', 443))

print repr(ssl_sock.getpeername())
print ssl_sock.cipher()
print pprint.pformat(ssl_sock.getpeercert())

# Set a simple HTTP request -- use httplib in actual code.
ssl_sock.write("""GET / HTTP/1.0\r
Host: www.verisign.com\r\n\r\n""")

# Read a chunk of data.  Will not necessarily
# read all the data returned by the server.
data = ssl_sock.read()

# note that closing the SSLSocket will also close the underlying socket
ssl_sock.close()