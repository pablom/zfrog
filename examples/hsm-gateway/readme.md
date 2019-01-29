This example demonstrates how you can use external libs in your application.

ctkmu j -s0 -aMPxDES -nZFROG_SSL server.p12

openssl pkcs12 -inkey server.key -in server.crt -export -out server.p12