zFrog socket connection example, that return all time
the same data back to every request

Note that this example only works if zfrog was built with CF_NOHTTP=1

Test:

	Connect to the server using openssl s_client, you will notice
	that anything sent is submitted back to your client.

	$ openssl s_client -connect 127.0.0.1:8888

