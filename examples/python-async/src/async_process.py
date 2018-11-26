#
# Asynchronous process example
#
# Wait for the result of an external process asynchronously.
# The handler will execute "/bin/ls" on the current directory and
# read the result.
#

import zfrog
import json

async def async_proc(req):
    #
    # You may specify a timeout when creating the zfrog.proc object.
    # If the timeout is reached before the process exits zfrog will
    # raise a TimeoutError exception.
    #
    # Ex: set timeout to 100ms:
    #   proc = zfrog.proc("/bin/ls -lR", 100)

    proc = zfrog.proc("/bin/ls -lR")

    try:
        stdout = ""

        # Read until EOF (None is returned)
        while True:
            chunk = await proc.recv(1024)
            if chunk is None:
                break
            stdout += chunk.decode()

        # Reap the process.
        retcode = await proc.reap()

        # Respond with the return code + the result as JSON.
        payload = {
            "retcode": retcode,
            "stdout": stdout
        }

        data = json.dumps(payload, indent=4)
        req.response(200, data.encode())
    except Exception as e:
        # If an exception occurs we must kill the process first.
        proc.kill()
        errmsg = "Exception: %s" % e
        req.response(500, errmsg.encode())
