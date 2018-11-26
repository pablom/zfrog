#
# Locking example
#
# The handler for /lock will grab the shared lock, suspend itself for
# 5 seconds before releasing the lock and responding.
#
# While the lock is held, other requests to /lock will block until it
# is released.

import zfrog

# The shared lock
lock = zfrog.lock()

async def async_lock(req):
    # A zfrog.lock should be used with the "async with" syntax.
    async with lock:
        # Suspend for 5 seconds.
        await zfrog.suspend(5000)

        # Now respond.
        req.response(200, b'')
