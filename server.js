//libraries and packages used
const net = require('net')
const fs = require('fs')
const crypto = require('crypto')
require('dotenv').config()

const PORT = process.env.PORT

//loading the certificates
const serverCrt = fs.readFileSync('server.crt')
const serverKey = fs.readFileSync('server.key')
const caCert = fs.readFileSync('ca.crt')

//function to encrypted the message
function encryptMessage(plaintext, key) {
    const iv = crypto.randomBytes(12); 
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([
        cipher.update(plaintext, 'utf8'),
        cipher.final()
    ]);

    const authTag = cipher.getAuthTag();

    return {
        iv: iv.toString('base64'),
        cipherText: encrypted.toString('base64'),
        tag: authTag.toString('base64')
    };
}

//function to send back message
let activeSocket = null
function sendSecureFromServer(text){
    if(!activeSocket || !activeSocket.handshakeDone){
        console.log("No Secure Client Connected Yet")
        return
    }

    const payload = encryptMessage(text, activeSocket.serverEncKey)
    activeSocket.write(JSON.stringify({
        type: "EncryptedMessage",
        data: payload
    }))
}

//function to decrypt the cipher
function decryptMessage(payload, key) {
    const iv = Buffer.from(payload.iv, 'base64');
    const ciphertext = Buffer.from(payload.cipherText, 'base64');
    const tag = Buffer.from(payload.tag, 'base64');

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
    ]);

    return decrypted.toString('utf8');
}

//sending the server certificate if client connects
const server = net.createServer((socket) => {
    activeSocket = socket
    //establishing the client hello
    socket.on('data', (data) => {
        const message = JSON.parse(data.toString());

        if(message.type === 'ClientHello'){
            //saving client random in buffer
            const clientRandom = Buffer.from(message.clientRandom, 'base64')
            //extracting the ecdh curve to be used
            const ecdhType = Buffer.from(message.ecdhType)
            //ecdh client pb key
            const clientEphemeralPk = Buffer.from(message.clientEphemeralPk, 'base64')
            //generating server random
            const serverRandom = crypto.randomBytes(64)
            //selecting the ecdh curve
            const ecdh = crypto.createECDH(ecdhType.toString())
            //generating the pvt key, then generating the pb key using G value defined in prime256v1
            ecdh.generateKeys();
            //getting the ecdh public key
            const serverEphemeralPk = ecdh.getPublicKey()
            //sign the ecdh public key by pvt RSA key of server
            const sign = crypto.createSign('sha256')
            sign.update(Buffer.concat([clientRandom, serverRandom, serverEphemeralPk]))
            sign.end()
            const signature = sign.sign(serverKey)


            //writing back to client an object containing server random & server certificate
            socket.write(
                JSON.stringify({
                    type: 'ServerHello',
                    serverRandom: serverRandom.toString('base64'),
                    serverCert: serverCrt.toString(),
                    ecdhPk: serverEphemeralPk.toString('base64'),
                    //for integrity
                    signature: signature.toString('base64'),
                })
            )
        
            socket.serverRandom = serverRandom
            socket.clientRandom = clientRandom
            socket.ecdh = ecdh

            const sharedSecret = ecdh.computeSecret(clientEphemeralPk)
            function deriveSessionKeys(sharedSecret, clientRandom, serverRandom){
                const salt = Buffer.concat([clientRandom, serverRandom])
                const keyMat = crypto.hkdfSync(
                        'sha256',
                        sharedSecret,
                        salt,
                        Buffer.from('handshake data'),
                        64
                    )
            
                return {
                    clientWKey: keyMat.slice(0,32),
                    serverWKey: keyMat.slice(32,64)
                }
            }

            const keys = deriveSessionKeys(sharedSecret, clientRandom, serverRandom);

            socket.serverEncKey = keys.serverWKey
            socket.clientDecKey = keys.clientWKey
            socket.handshakeDone = true
        }
        

        if(message.type === "EncryptedMessage"){
            try{
                const plaintext = decryptMessage(message.data, socket.clientDecKey)
                console.log("Client Says:", plaintext)

                if(plaintext == '/quit'){
                    console.log("Closing.")
                    socket.destroy()
                }
            }catch(e){
                console.error("Decryption/auth Failed", e.message)
                socket.destroy()
            }
        }
    })
})

//running the server on port 8080
server.listen(PORT, () => {
    console.log("Listening of Port:", PORT)
}) 

process.stdin.setEncoding('utf8')
process.stdin.on('data', (chunk) => {
    const text = chunk.trim();
    if (!text) return;
    if (text === '/quit') {
        console.log("Closing...");
        if (activeSocket) activeSocket.end();
        process.exit(0);
    }
  sendSecureFromServer(text);
})