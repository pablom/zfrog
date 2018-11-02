zFrog pure TCP/IP example

Note that this example only works if zfrog was built with CF_NO_HTTP=1

Test:

	Connect to the server using openssl s_client, you will notice
	that anything sent is submitted back to your client.

	$ openssl s_client -connect 127.0.0.1:8888

