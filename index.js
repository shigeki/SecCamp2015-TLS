var assert = require('assert'), crypto = require('crypto');
var DataReader = require('seccamp2015-data-reader').DataReader;

// Increment Number of Big Endian Bufffer
function incSeq(buf){
  var i;
  for(i=buf.length-1; i >= 0;i--){
    if(buf[i] < 0xff){
      buf[i]++;
      break;
    }
    buf[i] = 0x00;
  }
}

// TLS Content Type List
var type = {
  changecipherspec: 0x14,
  alert: 0x15,
  handshake: 0x16,
  application: 0x17
};
exports.ContentType = type;

// TLS HandshakeType List
var handshake_type = {
  clienthello: 0x01,
  serverhello: 0x02,
  certificate: 0x0b,
  serverkeyexchange: 0x0c,
  serverhellodone: 0x0e,
  clientkeyexchange: 0x10,
  finished: 0x14
};
exports.HandshakeType = handshake_type;

// write data to variable vector format with length field
function writeVector(data, floor, ceiling) {
  assert(data.length >= floor);
  assert(ceiling >= data.length);
  var vector_length = Math.ceil(ceiling.toString(2).length/8);
  var length = new Buffer(vector_length);
  length.writeUIntBE(data.length, 0, vector_length);
  return Buffer.concat([length, data]);
}

// check if reader has enough length to parse
exports.checkRecordHeader = checkRecordHeader;
function checkRecordHeader(reader) {
  if (5 > reader.bytesRemaining())
    return null;

  var length = reader.peekBytes(0, 5).readUIntBE(3, 2);
  if (length > reader.bytesRemaining())
    return null;

  return true;
}

// Create record buffer with adding header of TLS1.2
function createRecord(type, data) {
  var header = new Buffer(5);
  header[0] = type;
  header[1] = 0x03;
  header[2] = 0x03; // Explicitly used TLS1.2
  header.writeUIntBE(data.length, 3, 2);
  return Buffer.concat([header, data]);
}

// return json format of record header
function parseRecordHeader(reader) {
  assert(reader.bytesRemaining() >= 5);
  var type = reader.readBytes(1).readUInt8(0);
  var version = reader.readBytes(2);
  var length = reader.readBytes(2).readUIntBE(0, 2);
  return {type: type, version: version, length: length};
}

// add Handshake header in front of data
function createHandshake(type, data) {
  var header = new Buffer(4);
  header[0] = type;
  header.writeUIntBE(data.length, 1, 3);
  return Buffer.concat([header, data]);
}

exports.createClientHello = createClientHello;
function createClientHello(json, state) {
  state.handshake.clienthello = json;
  var version = json.version;
  var random = json.random;
  var session_id = writeVector(json.session_id, 0, 32);
  var cipher_suites = writeVector(Buffer.concat(json.cipher_suites), 2, 1 << 16 - 2);
  var compression = writeVector(json.compression, 0, 1 << 8 -1);
  var handshake = createHandshake(
    handshake_type.clienthello,
    Buffer.concat([version, random, session_id, cipher_suites, compression])
  );
  return createRecord(type.handshake, handshake);
}

function storeHandshakeData(reader, length, state) {
  // store handshake buffer data for session hash in Finished
  var handshake_msg_buf = reader.peekBytes(0, length);
  state.handshake_message_list.push(handshake_msg_buf);
}

exports.parseServerHello = parseServerHello;
function parseServerHello(reader, state) {
  if (!checkRecordHeader(reader))
    return null;

  var record_header = parseRecordHeader(reader);
  storeHandshakeData(reader, record_header.length, state);
  var type = reader.readBytes(1).readUInt8(0);
  var length = reader.readBytes(3).readUIntBE(0, 3);
  var version = reader.readBytes(2);
  var random = reader.readBytes(32);
  var session_id = reader.readVector(0, 32);
  var cipher = reader.readBytes(2);
  var compression = reader.readBytes(1);

  return {
    record_header: record_header,
    type: type,
    length: length,
    version: version,
    random: random,
    session_id: session_id,
    cipher: cipher,
    compression: compression
  };
}

exports.parseCertificate = parseCertificate;
function parseCertificate(reader, state) {
  if (!checkRecordHeader(reader))
    return null;

  var record_header = parseRecordHeader(reader);
  storeHandshakeData(reader, record_header.length, state);

  var type = reader.readBytes(1).readUInt8(0);
  var length = reader.readBytes(3).readUIntBE(0, 3);
  var cert_reader = new DataReader(reader.readBytes(length));
  var certlist = [];
  while(cert_reader.bytesRemaining() > 0) {
    var cert = cert_reader.readVector(0, 1 << 24 - 1);
    certlist.push(cert);
  }

  return {
    record_header: record_header,
    type: type,
    length: length,
    certlist: certlist
  };
}

exports.parseServerHelloDone = parseServerHelloDone;
function parseServerHelloDone(reader, state) {
  if (!checkRecordHeader(reader))
    return null;

  var record_header = parseRecordHeader(reader);
  storeHandshakeData(reader, record_header.length, state);

  var type = reader.readBytes(1).readUInt8(0);
  var length = reader.readBytes(3).readUIntBE(0, 3);

  return {
    record_header: record_header,
    type: type,
    length: length
  };
}

exports.parseServerFinished = parseServerFinished;
function parseServerFinished(reader, state) {
  if (!checkRecordHeader(reader))
    return null;

  var record_header = parseRecordHeader(reader);
  var handshake_msg_buf = reader.peekBytes(0, record_header.length);
  var type = reader.readBytes(1).readUInt8(0);
  var length = reader.readBytes(3).readUIntBE(0, 3);
  var verify_data = reader.readBytes(length);

  // Calculate session hash
  var shasum = crypto.createHash('sha256');
  shasum.update(Buffer.concat(state.handshake_message_list));
  var message_hash = shasum.digest();

  // Store Handshake data after hash caluclated
  state.handshake_message_list.push(handshake_msg_buf);

  var master_secret = state.keyblock.master_secret;

  // obtain session hash
  var r = PRF12(master_secret, "server finished", message_hash, 12);

  // Handshake integrity check
  assert(r.equals(verify_data));

  return {
    record_header: record_header,
    type: type,
    length: length,
    verify_data: verify_data
  };
}

exports.parseApplicationData = parseApplicationData;
function parseApplicationData(reader) {
  if (!checkRecordHeader(reader))
    return null;

  var record_header = parseRecordHeader(reader);
  var data = reader.readBytes(record_header.length);
  return {
    record_header: record_header,
    data: data
  };
}

// P_hash is defined in TLS1.2(RFC5246)
exports.P_hash = P_hash;
function P_hash(algo, secret, seed, size) {
  var result = (new Buffer(size)).fill(0);
  var hmac = crypto.createHmac(algo, secret);
  hmac.update(seed);
  var a = hmac.digest(); // A(1)
  var j = 0;
  while(j < size) {
    hmac = crypto.createHmac(algo, secret);
    hmac.update(a);
    hmac.update(seed);
    var b = hmac.digest();
    var todo = b.length;
    if (j + todo > size) {
      todo = size -j;
    }
    b.copy(result, j, 0, todo);
    j += todo;

    hmac = crypto.createHmac(algo, secret);
    hmac.update(a);
    a = hmac.digest(); // A(i+1)
  }

  return result;
}

// Pesuedo Random Function in TLS1.2 is sha256
exports.PRF12 = PRF12;
function PRF12(secret, label, seed, size) {
  var newSeed = Buffer.concat([new Buffer(label), seed]);
  return P_hash('sha256', secret, newSeed, size);
}

// Key Deviation Function for AES-128-GCM
exports.KDF = KDF;
function KDF(pre_master_secret, client_random, server_random) {
  var master_secret = PRF12(pre_master_secret, "master secret", Buffer.concat([client_random, server_random]), 48);
  // 40 bytes key_block for AES-128-GCM
  var key_block_reader = new DataReader(
    PRF12(master_secret, "key expansion", Buffer.concat([server_random, client_random]), 40));

  return {
    master_secret: master_secret,
    client_write_MAC_key: null,
    server_write_MAC_key: null,
    client_write_key: key_block_reader.readBytes(16),
    server_write_key: key_block_reader.readBytes(16),
    client_write_IV: key_block_reader.readBytes(4),
    server_write_IV: key_block_reader.readBytes(4)
  };
}

exports.createClientKeyExchange = createClientKeyExchange;
function createClientKeyExchange(json, state) {
  state.handshake.clientkeyexchange = json;
  var public_key = json.pubkey;
  var pre_master_secret = json.pre_master_secret;
  var encrypted = crypto.publicEncrypt({
    key: public_key,
    padding: require('constants').RSA_PKCS1_PADDING
  }, pre_master_secret);
  var encrypted_pre_master_secret = writeVector(encrypted, 0, 1 << 16 - 1);
  var handshake = createHandshake(handshake_type.clientkeyexchange, encrypted_pre_master_secret);
  return createRecord(type.handshake, handshake);
};

exports.createChangeCipherSpec = createChangeCipherSpec;
function createChangeCipherSpec() {
  return new Buffer('140303000101', 'hex');
};

exports.createClientFinished = createClientFinished;
function createClientFinished(json, state) {
  state.handshake.clientfinished = json;
  // create session hash
  var shasum = crypto.createHash('sha256');
  shasum.update(Buffer.concat(json.handshake_message_list));
  var message_hash = shasum.digest();
  var r = PRF12(json.master_secret, "client finished", message_hash, 12);
  var handshake = createHandshake(handshake_type.finished, r);
  return createRecord(type.handshake, handshake);
}

exports.createApplicationData = createApplicationData;
function createApplicationData(data) {
  return createRecord(type.application, data);
}

// pre_master_secret used only in RSA KeyExchange
exports.createPreMasterSecretRSAKeyExchange = createPreMasterSecretRSAKeyExchange;
function createPreMasterSecretRSAKeyExchange(version) {
  var pre_master_secret = Buffer.concat([version, crypto.randomBytes(46)]);
  return pre_master_secret;
}

exports.createKeyBlock = createKeyBlock;
function createKeyBlock(pre_master_secret, client_random, server_random) {
  var keyblock = KDF(pre_master_secret, client_random, server_random);
  return keyblock;
}

exports.sendClientKeyExchange = sendClientKeyExchange;
function sendClientKeyExchange(state) {
  var version = state.handshake.clienthello.version;
  var client_random = state.handshake.clienthello.random;
  var server_random = state.handshake.serverhello.random;
  var pre_master_secret = createPreMasterSecretRSAKeyExchange(version);
  state.keyblock = createKeyBlock(pre_master_secret, client_random, server_random);
  var clientkeyexchange = {
    pre_master_secret: pre_master_secret,
    pubkey: require('fs').readFileSync(__dirname + '/pubkey.pem')
  };
  var clientkeyexchange = createClientKeyExchange(clientkeyexchange, state);
  sendTLSFrame(clientkeyexchange, state);
}

exports.sendChangeCipherSpec = sendChangeCipherSpec;
function sendChangeCipherSpec(state) {
  var changecipherspec = createChangeCipherSpec();
  sendTLSFrame(changecipherspec, state);
  // After sending ChangeCipherSpec, sending frame is always encrypted.
  state.send_encrypted = true;
}

exports.sendClientFinished = sendClientFinished;
function sendClientFinished(state) {
  var clientfinished = {
    master_secret: state.keyblock.master_secret,
    handshake_message_list: state.handshake_message_list
  };
  var clientfinished = createClientFinished(clientfinished, state);
  sendTLSFrame(clientfinished, state);
}


// DeCipher that supports only aes-128-gcm
exports.Decrypt = Decrypt;
function Decrypt(encrypted, aad, key, iv, tag) {
  var decipher = crypto.createDecipheriv('aes-128-gcm', key, iv);
  decipher.setAuthTag(tag);
  decipher.setAAD(aad);
  var clear = decipher.update(encrypted);
  decipher.final();
  return clear;
}

exports.DecryptAEAD = DecryptAEAD;
function DecryptAEAD(reader, state) {
  if (!checkRecordHeader(reader))
    return null;

  var record_header = reader.readBytes(5);
  var length = record_header.readUIntBE(3, 2);
  var frame = reader.readBytes(length);
  var nonce_explicit = frame.slice(0, 8);
  var encrypted = frame.slice(8, frame.length - 16);
  var tag = frame.slice(-16);

  record_header.writeUIntBE(encrypted.length, 3, 2);

  var write_key = state.keyblock.server_write_key;
  var write_iv = state.keyblock.server_write_IV;
  var iv = Buffer.concat([write_iv.slice(0,4), nonce_explicit]);
  var aad = Buffer.concat([state.read_seq, record_header]);
  var clear = Decrypt(encrypted, aad, write_key, iv, tag);

  // re-calculate length with removing nonce_explict and tag length
  record_header.writeUIntBE(clear.length, 3, 2);

  // increment read sequence number
  incSeq(state.read_seq);

  return new DataReader(Buffer.concat(
    [record_header, clear, reader.readBytes(reader.bytesRemaining())]
  ));
}

// Cipher that supports only aes-128-gcm
exports.Encrypt = Encrypt;
function Encrypt(plain, key, iv, aad) {
  var cipher = crypto.createCipheriv('aes-128-gcm', key, iv);
  cipher.setAAD(aad);
  var encrypted1 = cipher.update(plain);
  var encrypted2 = cipher.final();
  var encrypted = Buffer.concat([encrypted1, encrypted2]);
  var tag = cipher.getAuthTag(tag);
  return {encrypted: encrypted, tag: tag};
}

exports.EncryptAEAD = EncryptAEAD;
function EncryptAEAD(frame, state) {
  var key = state.keyblock.client_write_key;
  var iv = Buffer.concat([state.keyblock.client_write_IV.slice(0,4), state.nonce_explicit]);
  var record_header = frame.slice(0, 5);
  var aad = Buffer.concat([state.write_seq, record_header]);

  var ret = Encrypt(frame.slice(5), key, iv, aad);
  var encrypted = ret.encrypted;
  var tag = ret.tag;

  // re-calcuate length with adding nonce_explit and tag length
  var length = state.nonce_explicit.length + encrypted.length + tag.length;
  record_header.writeUIntBE(length, 3, 2);

  // increment write sequence number
  incSeq(state.write_seq);

  var buf = Buffer.concat([record_header, state.nonce_explicit, encrypted, tag]);

  // increment nonce_explicit
  incSeq(state.nonce_explicit);
  return buf;
}

exports.sendTLSFrame = sendTLSFrame;
function sendTLSFrame(frame, state) {
  if (frame[0] === type.handshake)
    state.handshake_message_list.push(frame.slice(5));

  if (state.send_encrypted)
    frame = EncryptAEAD(frame, state);

  state.socket.write(frame);
}

// send all client's Handshake after receiving Certificate
exports.sendClientFrame = sendClientFrame;
function sendClientFrame(state) {
  sendClientKeyExchange(state);
  sendChangeCipherSpec(state);
  sendClientFinished(state);
}
