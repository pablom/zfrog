# Asynchronous postgresql queries with Python.

import json
import zfrog

# Register the path to our database when the worker starts.
def cf_worker_configure():
        zfrog.register_database("db", "host=/tmp dbname=zfrog")

# A handler that returns 200 OK with hello as body
def hello(req):
	req.response(200, b'hello\n')

#
# The query handler that fires of the query and returns a coroutine.
#
# zFrog will resume this handler when the query returns a result or
# is succesfull.
#
# The req.pgsql() method can throw exceptions, most notably a
# GeneratorExit in case the client connection went away before
# the query was able to be completed.
#
# In this example we're not doing any exception handling.
#
async def query(req):
	result = await req.pgsql("db", "SELECT * FROM coders")
	req.response(200, json.dumps(result).encode("utf-8"))

#
# A slow query that returns after 10 seconds
#
async def slow(req):
	result = await req.pgsql("db", "SELECT * FROM pg_sleep(10)")
	req.response(200, json.dumps(result).encode("utf-8"))
