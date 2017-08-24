# Using zfrog websockets via python.

import zfrog

#
# Our connection callback, gets called for each new websocket connection.
#
def onconnect(c):
	zfrog.log(zfrog.LOG_INFO, "%s: py connected" % c)

#
# Each websocket arriving on a connection triggers this function.
#
# It receives the connection object, the opcode (TEXT/BINARY) and the
# actual data received.
#
# In this example we use the websocket_broadcast() method from zfrog to
# simply relay the message to all other connection clients.
#
# If you want to send data directly back to the connection you can
# use zfrog.websocket_send(connection, op, data)
#
def onmessage(c, op, data):
	zfrog.websocket_broadcast(c, op, data, zfrog.WEBSOCKET_BROADCAST_GLOBAL)
	#c.websocket_send(op, data)

#
# Called for every connection that goes byebye.
#
def ondisconnect(c):
	zfrog.log(zfrog.LOG_INFO, "%s: py disconnecting" % c)

#
# The /ws connection handler. It establishes the websocket connection
# after a request was made for it.
#
# Note that the websocket_handshake() method for the request takes 3
# parameters which are the connection callback, message callback and
# disconnect callback.
#
# These are given as strings to zfrog which will then resolve them
# in all modules which means you can give native callbacks here as well.
#
def ws_connect(req):
	try:
		req.websocket_handshake("onconnect", "onmessage", "ondisconnect")
	except:
		req.response(500, b'')
