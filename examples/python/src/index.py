# This is a simple python module that can be loaded into zfrog
# It demonstrates some basic abilities to deal with HTTP requests

# Pull in the zfrog stuff.
import zfrog

# Pull in python JSON parsing.
import json

#
# A validator that the configuration for this application uses to determine
# if a request fulfills the requirements to pass an authentication block.
#
# See the configuration for more.
#
def python_auth(req, data):
	zfrog.log(zfrog.LOG_NOTICE, "python auth called %s" % data)
	return zfrog.RESULT_OK

#
# Define a validator that zfrog can use via the configuration to validate
# something before allowing access to it.
#
def python_validator(req, data):
	zfrog.log(zfrog.LOG_NOTICE, "python validator called %s" % data)
	return zfrog.RESULT_OK

#
# This function is called when our python module is loaded/unloaded.
# The action param is zfrog.MODULE_LOAD or zfrog.MODULE_UNLOAD respectively.
#
def onload(action):
	zfrog.log(zfrog.LOG_INFO, "python module onload called with %d!" % action)
	return zfrog.RESULT_OK

# Called by zfrog when the parent is starting
def cf_parent_configure():
	# Listen on an additional interface and port
	zfrog.listen("127.0.0.1", "8889", "")
	zfrog.log(zfrog.LOG_INFO, "cf_parent_configure called!")

# Called by zfrog when the worker is starting
def cf_worker_configure():
	zfrog.log(zfrog.LOG_INFO, "cf_worker_configure called!")

#
# Test page handler that displays some debug information as well as
# fetches the "xframe" header from the request and logs it if present.
#
# If the request is a POST then we read the body up to 1024 bytes in
# one go and display the result and bytes read in the log.
#
# If it's a GET request attempts to find the "id" argument and presents
# it to the user.
#
def page(req):
	zfrog.log(zfrog.LOG_INFO,
	    "%s path is %s - host is %s" % (req, req.path, req.host))
	zfrog.log(zfrog.LOG_INFO, "connection is %s" % req.connection)
	xframe = req.request_header("xframe")
	if xframe != None:
		zfrog.log(zfrog.LOG_INFO, "xframe header present: '%s'" % xframe)
	if req.method == zfrog.METHOD_POST:
		try:
			length, body = req.body_read(1024)
			zfrog.log(zfrog.LOG_INFO, "POST and got %d bytes! (%s)" %
			    (length, body.decode("utf-8")))
		except RuntimeError as r:
			zfrog.log(zfrog.LOG_INFO, "oops runtime error %s" % r)
			req.response(500, b'')
		except:
			zfrog.log(zfrog.LOG_INFO, "oops other error")
			req.response(500, b'')
		else:
			req.response_header("content-type", "text/plain")
			req.response(200, body)
	else:
		req.populate_get()
		id = req.argument("id")
		if id != None:
			zfrog.log(zfrog.LOG_INFO, "got id of %s" % id)
		req.response_header("content-type", "text/plain")
		req.response(200, "hello 1234".encode("utf-8"))

#
# Handler that parses the incoming body as JSON and dumps out some things
#
def json_parse(req):
	if req.method != zfrog.METHOD_PUT:
		req.response(400, b'')
	else:
		data = json.loads(req.body)
		zfrog.log(zfrog.LOG_INFO, "loaded json %s" % data)
		if data["hello"] == 123:
			zfrog.log(zfrog.LOG_INFO, "hello is 123!")

		req.response(200, "ok".encode("utf-8"))

#
# Small handler, returns 200 OK.
#
def minimal(req):
	req.response(200, b'')

#
# Small handler that grabs a cookie if set
#
def kkk(req):
	req.populate_cookies()
	cookie = req.cookie("hello")
	if cookie is not None:
		zfrog.log(zfrog.LOG_INFO, "got hello with value %s" % cookie)
	req.response(200, b'')
