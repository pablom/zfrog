
import zfrog
import socket

class EchoServer:
    # Setup socket + wrap it inside of a zfrog socket so we can use it
    def __init__(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        sock.bind(("127.0.0.1", 6969))
        sock.listen()        

        self.conn = zfrog.socket_wrap(sock)

    # Wait for a new client to connect, then create a new task
    # that calls handle_client with the connected client as
    # the argument
    async def run(self):
        while True:
            try:
                client = await self.conn.accept()
                zfrog.task_create(self.handle_client(client))
                client = None
            except Exception as e:
                zfrog.fatal("exception %s" % e)

    # Each client will run as this co-routine
    async def handle_client(self, client):
        while True:
            try:
                data = await client.recv(1024)
                if data is None:
                    break
                await client.send(data)
            except Exception as e:
                print("client got exception %s" % e)
        client.close()

# Setup the server object
server = EchoServer()

# Create a task that will execute inside of zfrog as a co-routine
zfrog.task_create(server.run())
