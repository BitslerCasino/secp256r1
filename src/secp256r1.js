const crypto = require('crypto');
const BN = require('bn.js');
const EC = require('elliptic').ec;

const messages = require('./messages.json');

const ec = new EC('p256');
const ecparams = ec.curve;

function loadPublicKey (publicKey) {
  return ec.keyFromPublic(publicKey);
}

exports.privateKeyVerify = privateKey => {
  const bn = new BN(privateKey);
  return bn.cmp(ecparams.n) < 0 && !bn.isZero()
}

exports.privateKeyExport = (privateKey, compressed) => {
  const d = new BN(privateKey);
  if (d.cmp(ecparams.n) >= 0 || d.isZero()) throw new Error(messages.EC_PRIVATE_KEY_EXPORT_DER_FAIL)

  return Buffer.from(ec.keyFromPrivate(privateKey).getPublic(compressed, true))
}

exports.privateKeyNegate = privateKey => {
  const bn = new BN(privateKey);
  return bn.isZero() ? Buffer.alloc(32) : ecparams.n.sub(bn).umod(ecparams.n).toBuffer('be', 32)
}

exports.privateKeyModInverse = privateKey => {
  const bn = new BN(privateKey);
  if (bn.cmp(ecparams.n) >= 0 || bn.isZero()) throw new Error(messages.EC_PRIVATE_KEY_RANGE_INVALID)

  return bn.invm(ecparams.n).toBuffer('be', 32)
}

exports.privateKeyTweakAdd = (privateKey, tweak) => {
  const bn = new BN(tweak);
  if (bn.cmp(ecparams.n) >= 0) throw new Error(messages.EC_PRIVATE_KEY_TWEAK_ADD_FAIL)

  bn.iadd(new BN(privateKey))
  if (bn.cmp(ecparams.n) >= 0) bn.isub(ecparams.n)
  if (bn.isZero()) throw new Error(messages.EC_PRIVATE_KEY_TWEAK_ADD_FAIL)

  return bn.toBuffer('be', 32)
}

exports.privateKeyTweakMul = (privateKey, tweak) => {
  let bn = new BN(tweak);
  if (bn.cmp(ecparams.n) >= 0 || bn.isZero()) throw new Error(messages.EC_PRIVATE_KEY_TWEAK_MUL_FAIL)

  bn.imul(new BN(privateKey))
  if (bn.cmp(ecparams.n)) bn = bn.umod(ecparams.n)

  return bn.toBuffer('be', 32)
}

exports.publicKeyCreate = (privateKey, compressed) => {
  const d = new BN(privateKey);
  if (d.cmp(ecparams.n) >= 0 || d.isZero()) throw new Error(messages.EC_PUBLIC_KEY_CREATE_FAIL)

  return Buffer.from(ec.keyFromPrivate(privateKey).getPublic(compressed, true))
}

exports.publicKeyConvert = (publicKey, compressed) => {
  const pair = loadPublicKey(publicKey);
  if (pair === null) throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)

  return Buffer.from(pair.getPublic(compressed, true))
}

exports.publicKeyVerify = publicKey => loadPublicKey(publicKey) !== null

exports.publicKeyTweakAdd = (publicKey, tweak, compressed) => {
  const pair = loadPublicKey(publicKey);
  if (pair === null) throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)

  tweak = new BN(tweak)
  if (tweak.cmp(ecparams.n) >= 0) throw new Error(messages.EC_PUBLIC_KEY_TWEAK_ADD_FAIL)

  return Buffer.from(ecparams.g.mul(tweak).add(pair.pub).encode(true, compressed))
}

exports.publicKeyTweakMul = (publicKey, tweak, compressed) => {
  const pair = loadPublicKey(publicKey);
  if (pair === null) throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)

  tweak = new BN(tweak)
  if (tweak.cmp(ecparams.n) >= 0 || tweak.isZero()) throw new Error(messages.EC_PUBLIC_KEY_TWEAK_MUL_FAIL)

  return Buffer.from(pair.pub.mul(tweak).encode(true, compressed))
}

exports.publicKeyCombine = (publicKeys, compressed) => {
  const pairs = new Array(publicKeys.length);
  for (let i = 0; i < publicKeys.length; ++i) {
    pairs[i] = loadPublicKey(publicKeys[i])
    if (pairs[i] === null) throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)
  }

  let point = pairs[0].pub;
  for (let j = 1; j < pairs.length; ++j) point = point.add(pairs[j].pub)
  if (point.isInfinity()) throw new Error(messages.EC_PUBLIC_KEY_COMBINE_FAIL)

  return Buffer.from(point.encode(true, compressed))
}

exports.signatureNormalize = signature => {
  const r = new BN(signature.slice(0, 32));
  const s = new BN(signature.slice(32, 64));
  if (r.cmp(ecparams.n) >= 0 || s.cmp(ecparams.n) >= 0) throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL)

  const result = Buffer.from(signature);
  if (s.cmp(ec.nh) === 1) ecparams.n.sub(s).toBuffer('be', 32).copy(result, 32)

  return result
}

exports.signatureExport = signature => {
  const r = signature.slice(0, 32);
  const s = signature.slice(32, 64);
  if (new BN(r).cmp(ecparams.n) >= 0 || new BN(s).cmp(ecparams.n) >= 0) throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL)

  return { r, s };
}

exports.signatureImport = sigObj => {
  let r = new BN(sigObj.r);
  if (r.cmp(ecparams.n) >= 0) r = new BN(0)

  let s = new BN(sigObj.s);
  if (s.cmp(ecparams.n) >= 0) s = new BN(0)

  return Buffer.concat([
    r.toBuffer('be', 32),
    s.toBuffer('be', 32)
  ])
}

exports.sign = (message, privateKey, noncefn, data) => {
  if (typeof noncefn === 'function') {
    const getNonce = noncefn;
    noncefn = counter => {
      const nonce = getNonce(message, privateKey, null, data, counter);
      if (!Buffer.isBuffer(nonce) || nonce.length !== 32) throw new Error(messages.ECDSA_SIGN_FAIL)

      return new BN(nonce)
    }
  }

  const d = new BN(privateKey);
  if (d.cmp(ecparams.n) >= 0 || d.isZero()) throw new Error(messages.ECDSA_SIGN_FAIL)

  const result = ec.sign(message, privateKey, { canonical: true, k: noncefn, pers: data });
  return {
    signature: Buffer.concat([
      result.r.toBuffer('be', 32),
      result.s.toBuffer('be', 32)
    ]),
    recovery: result.recoveryParam
  }
}

exports.verify = (message, signature, publicKey) => {
  if(signature.length !== 64) throw new Error(messages.ECDSA_SIGNATURE_LENGTH_INVALID)
  const sigObj = {r: signature.slice(0, 32), s: signature.slice(32, 64)};

  const sigr = new BN(sigObj.r);
  const sigs = new BN(sigObj.s);
  if (sigr.cmp(ecparams.n) >= 0 || sigs.cmp(ecparams.n) >= 0) throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL)
  if (sigs.cmp(ec.nh) === 1 || sigr.isZero() || sigs.isZero()) return false

  const pair = loadPublicKey(publicKey);
  if (pair === null) throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)

  return ec.verify(message, sigObj, {x: pair.pub.x, y: pair.pub.y})
}

exports.recover = (message, signature, recovery, compressed) => {
  const sigObj = {r: signature.slice(0, 32), s: signature.slice(32, 64)};

  const sigr = new BN(sigObj.r);
  const sigs = new BN(sigObj.s);
  if (sigr.cmp(ecparams.n) >= 0 || sigs.cmp(ecparams.n) >= 0) throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL)

  try {
    if (sigr.isZero() || sigs.isZero()) throw new Error()

    const point = ec.recoverPubKey(message, sigObj, recovery);
    return Buffer.from(point.encode(true, compressed))
  } catch (err) {
    throw new Error(messages.ECDSA_RECOVER_FAIL)
  }
}

exports.ecdh = (publicKey, privateKey) => {
  const shared = exports.ecdhUnsafe(publicKey, privateKey, true);
  return crypto.createHash('sha256').update(shared).digest()
}

exports.ecdhUnsafe = (publicKey, privateKey, compressed) => {
  const pair = loadPublicKey(publicKey);
  if (pair === null) throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)

  const scalar = new BN(privateKey);
  if (scalar.cmp(ecparams.n) >= 0 || scalar.isZero()) throw new Error(messages.ECDH_FAIL)

  return Buffer.from(pair.pub.mul(scalar).encode(true, compressed))
}
