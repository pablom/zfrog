
Lightweight, high performance Web application framework.

[![Build Status](https://travis-ci.org/pablom/zfrog.svg?branch=master)](https://travis-ci.org/pablom/zfrog)
[![Coverity Status](https://img.shields.io/coverity/scan/12489.svg)](https://scan.coverity.com/projects/pablom-zfrog)


Platforms supported
-------------------
* Linux
* OpenBSD
* FreeBSD
* OSX

More information can be found on https://zfrog.xyz

Building zFrog
-------------

Requirements
* openssl (1.0.2k or 1.1.0g)
  (note: this requirement drops away when building with CF_NOTLS=1 CF_NOHTTP=1)
  (note: libressl should work as a replacement)

Requirements for background tasks (optional)
* pthreads

Requirements for python (optional)
* Python 3.6+

Requirements for pgsql (optional)
* libpq

If you would like to build a specific flavor, you can enable
those by setting a shell environment variable before running **_make_**.

* CF_TASKS=1  (compiles in task support)
* CF_PGSQL=1  (compiles in pgsql support)
* CF_DEBUG=1  (enables use of -d for debug)
* CF_NOTLS=1  (compiles zfrog without TLS)
* CF_NOHTTP=1 (compiles zfrog without HTTP support)
* CF_JSONRPC=1 (compiles in JSONRPC support)
* CF_PYTHON=1  (compiles in the Python support)
* CF_LUA=1     (compiles in the Lua support)
* CF_REDIS=1   (compiles in the Redis support)
