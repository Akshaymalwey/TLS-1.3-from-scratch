I Have made TLS 1.3 from scratch using ECDHE.

1) Generated the Private and Public Keys by using RSA and simple openssl.
2) Created three bodies, a client, a server and a root CA (certifying authority) that is self certified.
3) Certified both the client and the server by the root CA.
4) Now, first, the client will initiate the communication by sending a "Client-Hello".
5) CLien-Hello will have, the ecdh type that client is compatible for, a client random and client's ephemeral public key that it generates.
6) Now, ecdh type that I am using is "prime256v1" and it conveys what curve are we using and what G value are we using. 
7) Next, this get's received by the server, it saves it all in its buffer and sends back a Server-Hello.
8) In Server-Hello we have, a server random, the server certificate (certified by our root CA), server's ephemeral public key that it too generates based on the G value that it received and a signature on the client random, the server random and the ephemeral key by the private key of server that will make sure the integrity is not compromised.
9) Next, the client will receive all this and it firstly will perform the signature verfication, by decrypting it by the public key of server that it has received from the server certificate, then it will do a certificate chain validation on the certificate by checking the root CA that has authorised is the one that the client also trusts. 
10) Now, that this is done. Both the client and server will now generate a shared-secret key using server's ephemeral public key and client's ephemeral private key and client's ephemeral public key and server's ephemeral private key respectivily. 
11) By this both will end up with a shared secret key that will come out to be the same on both sides.
12) Next they will create the session keys by using this shared-secret hashing is with a concatination of client-random and server-random using SHA-256.
13) Now, for this session key the first half can be using (0-32 bits) for Client keys and the other half (32, 64 bits) can be used for Server keys. 
14) Then, both the client and the server sends a dummy text, the get's encrypted using AES-256.
15) Next, whatever we type on the CLI it can we transfered from client side to server side and vice versa.
16) Typing "/quit" will close the socket connection.