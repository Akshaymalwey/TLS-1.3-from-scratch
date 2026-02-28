//libraries and packages used
const net = require('net')
const fs = require('fs')
const crypto = require('crypto')
const forge = require('node-forge')
require('dotenv').config()

const PORT = process.env.PORT

//loading the certificates
const clientCrt = fs.readFileSync('client.crt')
const clientKey = fs.readFileSync('client.key')
const caCert = fs.readFileSync('ca.crt')

//generating client random
const clientRandom = crypto.randomBytes(64)

//establishing the connection
const client = net.createConnection({port: PORT}, () => {
    console.log("Connected to Server!")
})

//creating client ECDH key pairs
const clientECDH = crypto.createECDH('prime256v1')
clientECDH.generateKeys()

//extracting public key
const clientEphemeralPk = clientECDH.getPublicKey()

//functions to derive the session keys
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

//function to encrypting the message
function encryptMessage(plaintext, key){
    const iv = crypto.randomBytes(12)
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
    const encrypted = Buffer.concat([
        cipher.update(plaintext, 'utf8'),
        cipher.final()
    ])
    const authTag = cipher.getAuthTag();

    return {
        iv: iv.toString('base64'),
        cipherText: encrypted.toString('base64'),
        tag: authTag.toString('base64')
    }

}

//function to send any text securely
function sendSecure(text){
    if(!client.handshakeDone){
        console.log("Handshake is not done yet so, message not sent.")
        return
    }

    const payload = encryptMessage(text, client.clientEncKey)
    client.write(JSON.stringify({
        type: "EncryptedMessage",
        data: payload
    }))

}

//function to decrypting the cipher
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

//sending client random when establishing the connection
client.write(
    JSON.stringify({
        type: "ClientHello",
        ecdhType: "prime256v1",
        clientRandom: clientRandom.toString('base64'),
        clientEphemeralPk: clientEphemeralPk.toString('base64')
    })
)

//fetching the data, that has been received from server running on port 8080
client.on('data', (data) => {
    //extracting the object receieved from server
    const message = JSON.parse(data.toString())

    if(message.type === "ServerHello"){
        const serverRandom = Buffer.from(message.serverRandom, 'base64')
        const serverEphemeralPk = Buffer.from(message.ecdhPk, 'base64')
        const signature = Buffer.from(message.signature, 'base64')
        const serverPem = message.serverCert
        const caPem = caCert.toString();

        //verifies the hash
        const verify = crypto.createVerify('sha256')
        verify.update(Buffer.concat([clientRandom, serverRandom, serverEphemeralPk]))
        verify.end()

        const isValid = verify.verify(serverPem, signature)
        if(!isValid){
            //preventing MITM
            throw new Error('ECDHE key signature invalid')
        }

        //fetching the certification credentials
        const serverCert = forge.pki.certificateFromPem(serverPem)
        const caCertificate = forge.pki.certificateFromPem(caPem)
        const caStore = forge.pki.createCaStore([caCertificate])

        //simple try-catch block for verification of certificate chain validation
        try{
            forge.pki.verifyCertificateChain(caStore, [serverCert])
            console.log("Server Certificate Verified Successfully!")
        } catch(e){
            console.log("Verification Failed", e)
            //client end is verification failied.
            client.end()
        }

        client.serverRandom = serverRandom
        client.ecdh = clientECDH

        const sharedSecret = clientECDH.computeSecret(serverEphemeralPk)
        const keys = deriveSessionKeys(sharedSecret, clientRandom, serverRandom);
        client.clientEncKey = keys.clientWKey
        client.serverDecKey = keys.serverWKey
        client.handshakeDone = true

        const payload = encryptMessage("Hello Server", client.clientEncKey)
        client.write(JSON.stringify({ 
            type: "EncryptedMessage", 
            data: payload 
        }));
    }

    if(message.type === "EncryptedMessage"){
        try{
            const plaintext = decryptMessage(message.data, client.serverDecKey)
            console.log("Server Says:", plaintext)
        }catch(e){
            console.error("Decryption/auth Failed", e.message)
            client.destroy()
        }
    }
})

process.stdin.setEncoding('utf8')
process.stdin.on('data', (chunk) => {
    const text = chunk.trim();
    if(!text) return

    if(text == '/quit'){
        sendSecure(text)
        console.log("Closing.")
        client.end()
        process.exit(0)
    }

    sendSecure(text)
})