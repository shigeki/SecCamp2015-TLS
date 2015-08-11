var crypto = require('crypto');
var PRF12 = require('seccamp2015-tls').PRF12;

var pre_master_secret = crypto.randomBytes(48);
var client_random = crypto.randomBytes(32);
var server_random = crypto.randomBytes(32);

function MyPRF12(secret, label, seed, size) {
  return MyP_hash('sha256', secret, Buffer.concat([label, seed]), size);
}

var label = new Buffer("master secret");
var master_secret = PRF12(pre_master_secret, label, Buffer.concat([client_random, server_random]), 48);
var Mymaster_secret = MyPRF12(pre_master_secret, label, Buffer.concat([client_random, server_random]), 48);

console.log(master_secret);
console.log(Mymaster_secret);
console.log(master_secret.equals(Mymaster_secret));

function MyP_hash(algo, secret, seed, size) {
  var ret = new Buffer(size);
  var hmac = crypto.createHmac(algo, secret);
  hmac.update(seed);
  var a = hmac.digest(); // A(1)
  var end = 0;
  while(size > end) {
    hmac = crypto.createHmac(algo, secret);
    hmac.update(Buffer.concat([a, seed]));
    var b = hmac.digest();
    var len = (size - end >= b.length) ? b.length: size - end;
    b.copy(ret, end, 0, len);
    end += len;
    hmac = crypto.createHmac(algo, secret);
    hmac.update(a);
    a = hmac.digest(); // A(i+1)
  }
  return ret;
}
