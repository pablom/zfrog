zfrog python module example.

This application requires zfrog to be built with CF_PYTHON=1

It mixes native code (dso) with python code.


Test:

	$ curl -k https://127.0.0.1:8888
	$ curl -k https://127.0.0.1:8888/state
	$ curl -k https://127.0.0.1:8888/auth
	$ curl -X PUT -d '{\"hello\": 123}' https://127.0.0.1:8888/json

