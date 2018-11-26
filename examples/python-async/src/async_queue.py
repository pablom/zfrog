#
# Asynchronous queue example
#

import zfrog

# The shared queue.
tq = zfrog.queue()

# Entry point for our independent coroutine that is created when zfrog starts.
async def queue_helper():
    while True:
        # Wait for a dictionary to arrive.
        obj = await tq.pop()
        zfrog.log(zfrog.LOG_INFO, "coro(): received %s" % obj)

        # Create a message to send back.
        msg = "%d = %s" % (zfrog.time(), obj["msg"])

        # Send it on the received queue.
        obj["rq"].push(msg)

async def async_queue(req):
    # Create our own queue.
    rq = zfrog.queue()

    # The dictionary we are going to send.
    obj = {
        # Receive queue object.
        "rq": rq,
        "msg": "hello"
    }

    # Push it onto the tq queue now, which will wake up the other coroutine.
    tq.push(obj)

    # Wait for a response.
    response = await rq.pop()

    # Send the response to the client.
    req.response(200, response.encode())
