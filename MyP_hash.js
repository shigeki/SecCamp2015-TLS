var crypto = require('crypto');
var P_hash = require('seccamp2015-tls').P_hash;
var algo = 'sha256';
var secret = 'secret';
var seed = (new Buffer(32)).fill(0);
var size = 48;

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

var answer = P_hash(algo, secret, seed, size);
console.log(answer);

var my_answer = MyP_hash(algo, secret, seed, size);
console.log(my_answer);

console.log(answer.equals(my_answer));
