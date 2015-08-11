var net = require('net');
var crypto = require('crypto');
var DataReader = require('seccamp2015-data-reader').DataReader;
var recordheader = '160301002D';
var random = crypto.randomBytes(32).toString('hex');
var handshake = '010000290303' + random + '000002009C0100';
var clienthello = new Buffer(recordheader + handshake, 'hex');
var client = net.connect({host: 'tls.koulayer.com', port: 443}, function() {
  client.write(clienthello);
});
client.on('data', function(c) {
  var reader = new DataReader(c);
  if (reader.peekBytes(5, 6).readUInt8(0) === 0x02) {
    var serverhello = parseServerHello(reader);
    console.log(serverhello);
    client.end();
  }
});

function parseRecordHeader(reader) {
  var type = reader.readBytes(1).readUInt8(0);
  var version = reader.readBytes(2);
  var length = reader.readBytes(2).readUIntBE(0, 2);
  return {type: type, version: version, length: length};
}

function parseServerHello(reader) {
  var record_header = parseRecordHeader(reader);
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
