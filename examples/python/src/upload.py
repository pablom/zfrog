# Processing incoming files in a multipart form

import zfrog

#
# This handler receives a POST with a multipart data.
# It extracts the file called "file" and writes it to a new file.
#
def upload(req):
	# We only allow POST's
	if req.method is not zfrog.METHOD_POST:
		req.response_header("allow", "post")
		req.response(400, b'')
		return

	# Ask zfrog to parse incoming multipart data
	req.populate_multi()

	# Lookup the file called "file"
	file = req.file_lookup("file")
	if not file:
		req.response(400, b'')
		return

	zfrog.log(zfrog.LOG_INFO,
	    "%s (%s, filename=%s)" % (file, file.name, file.filename))

	# Open target file
	f = open(file.filename, "wb")
	if not f:
		req.response(500, b'')
		return

	# Read all data from incoming file and write it to the output file
	len = True
	while len:
		len, bytes = file.read(1024)
		zfrog.log(zfrog.LOG_INFO, "got %d bytes of data" % len)
		f.write(bytes)

	f.close()
	req.response(200, b'')
