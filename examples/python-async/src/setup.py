
import zfrog

from async_queue import queue_helper

# zfrog worker started, start the queue helper coroutine
def cf_worker_configure():
    zfrog.task_create(queue_helper())
