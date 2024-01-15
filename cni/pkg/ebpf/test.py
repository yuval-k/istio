import socket

a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# set mark on the socket
a.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 1337)
a.bind(("127.0.0.1", 15008))

a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
a.bind(("127.0.0.1", 15008))