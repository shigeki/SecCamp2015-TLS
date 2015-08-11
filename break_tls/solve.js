var DataReader = require('seccamp2015-data-reader').DataReader;
var SecCampTLS = require('seccamp2015-tls');
var fs = require('fs');
var crypto = require('crypto');
var handshake = require(__dirname + '/handshake.json');
var clienthello = new Buffer(handshake.ClientHello, 'hex');
var serverhello = new Buffer(handshake.ServerHello, 'hex');
var clientkeyexchange = new Buffer(handshake.ClientKeyExchange, 'hex');
var encryptedApplicationData = new Buffer(handshake.EncryptedApplicationData, 'hex');
// obtain handshake parameters
var client_random = clienthello.slice(11, 11+32);
var server_random = serverhello.slice(11, 11+32);
var encrypted_pre_master_secret = clientkeyexchange.slice(11);
// obtain private key
var private_key = fs.readFileSync(__dirname + '/server.key');
// decrypt pre master secret
var pre_master_secret = crypto.privateDecrypt(
  {key: private_key,
   padding: require('constants').RSA_PKCS1_PADDING
  }, encrypted_pre_master_secret);
// objtain keyblock
var keyblock = SecCampTLS.KDF(pre_master_secret, client_random, server_random);
// Calculate Sequence Number
var read_seq = (new Buffer(8)).fill(0);
read_seq[7] = 0x01;
// Obtain AEAD parameters
var reader = new DataReader(encryptedApplicationData);
var record_header = reader.readBytes(5);
var length = record_header.readUIntBE(3, 2);
var frame = reader.readBytes(length);
var nonce_explicit = frame.slice(0, 8);
var encrypted = frame.slice(8, frame.length - 16);
var tag = frame.slice(-16);
// Re-Caluclate record header
record_header.writeUIntBE(encrypted.length, 3, 2);
var iv = Buffer.concat([keyblock.client_write_IV, nonce_explicit]);
var aad = Buffer.concat([read_seq, record_header]);
// Decrypt Application Data
var decipher = crypto.createDecipheriv('aes-128-gcm', keyblock.client_write_key, iv);
decipher.setAuthTag(tag);
decipher.setAAD(aad);
var clear = decipher.update(encrypted);
decipher.final();
console.log(clear.toString());
