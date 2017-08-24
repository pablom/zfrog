zfrog as a TLS-proxy

Edit src/proxy.c and add your backends to the backends[] data structure

If you want to reduce attack surface you can build zfrog with CF_NOHTTP=1 to
completely remove the HTTP component and only run the net code.


Test:

	Connect to the server and notice that it proxies data between you
	and your destination.

	$ openssl s_client -connect 127.0.0.1:8888

