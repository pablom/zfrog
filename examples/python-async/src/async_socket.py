#
# Simple socket example
#
# The handler will asynchronously connect to the zfrog app itself and
# send an GET request to /socket-test and read the response.

import zfrog
import socket

async def async_socket(req):
    # Create the socket using Pythons built-in socket class.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Set it to nonblocking.
    sock.setblocking(False)

    # Create a zfrog.socket with zfrog.socket_wrap().
    conn = zfrog.socket_wrap(sock)

    # Asynchronously connect to 127.0.0.1 port 8888
    await conn.connect("127.0.0.1", 8888)
    zfrog.log(zfrog.LOG_INFO, "connected!")

    # Now send the GET request
    msg = "GET /socket-test HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
    await conn.send(msg.encode())
    zfrog.log(zfrog.LOG_INFO, "request sent!")

    # Read the response.
    data = await conn.recv(8192)
    zfrog.log(zfrog.LOG_INFO, "got response!")

    # Respond with the response from /socket-test.
    req.response(200, data)

    # Close the underlying socket, no need to close the wrapped zfrog.socket
    sock.close()

async def socket_test(req):
    # Delay response a bit, just cause we can.
    await zfrog.suspend(5000)
    req.response(200, b'response from /socket-test')
