var assert = require('assert');
var net = require('net');
var crypto = require('crypto');
var DataReader = require('seccamp2015-data-reader').DataReader;
var SecCampTLS = require('seccamp2015-tls');


var ContentType = SecCampTLS.ContentType;
var HandshakeType = SecCampTLS.HandshakeType;

// TLS State Object to store secure parameters
function TLSState(socket, is_server) {
  this.is_server = is_server;
  this.socket = socket;
  this.send_encrypted = false;
  this.recv_encrypted = false;
  this.keyblock = {};
  this.handshake_message_list = [];
  this.handshake = {};
  this.nonce_explicit = crypto.randomBytes(8);
  this.write_seq = (new Buffer(8)).fill(0);
  this.read_seq = (new Buffer(8)).fill(0);
}

// Initial ClientHello Data
var clienthello = {
  version: new Buffer('0303', 'hex'),
  random: crypto.randomBytes(32),
  session_id: new Buffer(0),
  cipher_suites: [new Buffer('009C', 'hex')],
  compression: new Buffer('00', 'hex')
};

var host = 'tls.koulayer.com';
var port = 443;

var client = net.connect({host: host, port: port}, function() {
  var state = new TLSState(client, false);

  // initial remaining buffer is zero
  var remaining = new Buffer(0);
  client.on('data', function(c) {
    // create data reader with cocatinating of remaining buffer and receiving data
    var reader = new DataReader(Buffer.concat([remaining, c]));
    // parse TLS Frame from reader
    parseFrame(reader, state);
    // store remaining buffer after parsing TLS frame
    remaining = reader.readBytes(reader.bytesRemaining());
  });

  client.on('secureConnection', function() {
    // After handshake completed, stdin data is sent to server with encryption
    process.stdin.on('data', function(c) {
      var applicationData = SecCampTLS.createApplicationData(c);
      SecCampTLS.sendTLSFrame(applicationData, state);
    });
  });

  // send initial ClientHello to server
  var clienthelloFrame = SecCampTLS.createClientHello(clienthello, state);
  SecCampTLS.sendTLSFrame(clienthelloFrame, state);
});


function parseFrame(reader, state) {
  // The more than the size of header record are needed to parse TLS frame
  if (!reader || 5 > reader.bytesRemaining())
    return;

  // After ChangeCipherSpec received, all received frame are encrypted.
  if (state.recv_encrypted)
    reader = SecCampTLS.DecryptAEAD(reader, state);

  var type = reader.peekBytes(0, 1).readUInt8(0);
  switch(type) {
  case ContentType.changecipherspec:
    console.log('ChangeCipherSpec Received');
    // Check KeyExchange was already completed.
    assert(state.keyblock.master_secret, 'Not Key Negotiated Yet');
    reader.readBytes(6);
    state.recv_encrypted = true;
    break;
  case ContentType.alert:
    console.log('TLS Alert Received');
    // ToDo implement. just return.
    return;
    break;
  case ContentType.handshake:
    reader = parseHandshake(reader, state);
    break;
  case ContentType.application:
    console.log('Application Data Received');
    var data = SecCampTLS.parseApplicationData(reader);
    console.log(data.data);
    break;
  default:
    throw new Error('Unknown msg type:' + type);
  }
  parseFrame(reader, state);
};

// if reader does not have enough length to be parsed, then return null;
// This puts all data buffer of reader into remaining buffer.
function parseHandshake(reader, state) {
  var json = state.handshake;
  var type = reader.peekBytes(5, 6).readUInt8(0);
  switch(type) {
  case HandshakeType.serverhello:
    if (!(json.serverhello = SecCampTLS.parseServerHello(reader, state)))
      return null;

    console.log('Server Hello Received');
    break;
  case HandshakeType.certificate:
    if (!(json.certificate = SecCampTLS.parseCertificate(reader, state)))
      return null;

    console.log('Certificate Received');
    break;
  case HandshakeType.serverhellodone:
    if (!(json.serverhellodone = SecCampTLS.parseServerHelloDone(reader, state)))
      return null;

    console.log('ServerHelloDone Received');
    sendClientFrame(state);
    break;
  case HandshakeType.finished:
    if(!(json.serverfinished = SecCampTLS.parseServerFinished(reader, state)))
      return null;

    console.log('ServerFinished Received');
    console.log('Handshake Completed');
    // After handshake complete, secureConnection event is emitted to parse stdin
    state.socket.emit('secureConnection');
    break;
  default:
    throw new Error('Unknown handshake type:' +  type);
  }
  return reader;
}

function sendClientFrame(state) {
  SecCampTLS.sendClientKeyExchange(state);
  console.log('ClientKeyExchange Sent');
  SecCampTLS.sendChangeCipherSpec(state);
  console.log('ChangeCipherSpec Sent');
  SecCampTLS.sendClientFinished(state);
  console.log('ClientFinished Sent');
}
