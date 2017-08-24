local ffi = require("ffi")
ffi.cdef[[
unsigned long compressBound(unsigned long sourceLen);
int compress2gzip(uint8_t *dest, unsigned long *destLen,
		const uint8_t *source, unsigned long sourceLen, int level);
]]

local zlib = ffi.load("z")
local gzlib = ffi.load("./gzlib.so")

function compress(txt, level)
	local n = zlib.compressBound(#txt)
	local buf = ffi.new("uint8_t[?]", n)
	local buflen = ffi.new("unsigned long[1]", n)
	local res = gzlib.compress2gzip(buf, buflen, txt, #txt, level)
	assert(res == 0)
	return ffi.string(buf, buflen[0])
end


function onload()
	print('lua: onload')
end

function f(req)
	output = compress("ABCDABCDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 9)
	print(output)
    req:response('It works')
end
