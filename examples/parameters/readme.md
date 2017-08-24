Example on how to handle GET/POST parameters in zfrog

Test:

	# curl -i -k https://127.0.0.1:8888/?id=123123

The output will differ based on wether or not id is a valid
uint16_t number or not. (the string should always be present)
