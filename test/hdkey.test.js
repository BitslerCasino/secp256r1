const assert = require('assert');
const BigInteger = require('bigi');
const ecurve = require('ecurve');
const curve = ecurve.getCurveByName('secp256k1');
const secureRandom = require('secure-random')
const HDKey = require('../src/hdkey');
const fixtures = require('./fixtures/hdkey');


describe('hdkey', () => {
  describe('+ fromMasterSeed', () => {
    fixtures.valid.forEach(f => {
      it(`should properly derive the chain path: ${f.path}`, () => {
        const hdkey = HDKey.fromMasterSeed(Buffer.from(f.seed, 'hex'));
        const childkey = hdkey.derive(f.path);

        assert.equal(childkey.privateExtendedKey, f.private)
        assert.equal(childkey.publicExtendedKey, f.public)
      })

      describe(`> ${f.path} toJSON() / fromJSON()`, () => {
        it('should return an object read for JSON serialization', () => {
          const hdkey = HDKey.fromMasterSeed(Buffer.from(f.seed, 'hex'));
          const childkey = hdkey.derive(f.path);

          const obj = {
            xpriv: f.private,
            xpub: f.public
          };

          assert.deepEqual(childkey.toJSON(), obj)

          const newKey = HDKey.fromJSON(obj);
          assert.strictEqual(newKey.privateExtendedKey, f.private)
          assert.strictEqual(newKey.publicExtendedKey, f.public)
        })
      })
    })
  })

  describe('- privateKey', () => {
    it('should throw an error if incorrect key size', () => {
      const hdkey = new HDKey();
      assert.throws(() => {
        hdkey.privateKey = Buffer.from([1, 2, 3, 4])
      }, /key must be 32/)
    })
  })

  describe('- publicKey', () => {
    it('should throw an error if incorrect key size', () => {
      assert.throws(() => {
        const hdkey = new HDKey();
        hdkey.publicKey = Buffer.from([1, 2, 3, 4])
      }, /key must be 33 or 65/)
    })

    it('should not throw if key is 33 bytes (compressed)', () => {
      const priv = Buffer.from('026522ac563606774a2f9938b09667aa2bee38d26e2864c61aae0f2aed8a67748f')
      const pub = curve.G.multiply(BigInteger.fromBuffer(priv)).getEncoded(true);
      assert.equal(pub.length, 33)
      const hdkey = new HDKey();
      hdkey.publicKey = pub
    })

    it('should not throw if key is 65 bytes (not compressed)', () => {
      const priv = secureRandom.randomBuffer(65);
      const pub = curve.G.multiply(BigInteger.fromBuffer(priv)).getEncoded(false);
      assert.equal(pub.length, 65)
      const hdkey = new HDKey();
      hdkey.publicKey = pub
    })
  })

  describe('+ fromExtendedKey()', () => {
    describe('> when private', () => {
      it('should parse it', () => {
        // m/0/2147483647'/1/2147483646'/2
        const key = 'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j';
        const hdkey = HDKey.fromExtendedKey(key);
        assert.equal(hdkey.versions.private, 0x0488ade4)
        assert.equal(hdkey.versions.public, 0x0488b21e)
        assert.equal(hdkey.depth, 5)
        assert.equal(hdkey.parentFingerprint, 0x31a507b8)
        assert.equal(hdkey.index, 2)
        assert.equal(hdkey.chainCode.toString('hex'), '9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271')
        assert.equal(hdkey.privateKey.toString('hex'), 'bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23')
        assert.equal(hdkey.publicKey.toString('hex'), '03e54570a9eb5b8378850f4e9bde4b6008834263b3cf454baa818107e4f0edf675')
        assert.equal(hdkey.identifier.toString('hex'), '8a0abfc573a9b1ec924f674c29a70e726baaf4e6')
      })
    })

    describe('> when public', () => {
      it('should parse it', () => {
        // m/0/2147483647'/1/2147483646'/2
        const key = 'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt';
        const hdkey = HDKey.fromExtendedKey(key);
        assert.equal(hdkey.versions.private, 0x0488ade4)
        assert.equal(hdkey.versions.public, 0x0488b21e)
        assert.equal(hdkey.depth, 5)
        assert.equal(hdkey.parentFingerprint, 0x31a507b8)
        assert.equal(hdkey.index, 2)
        assert.equal(hdkey.chainCode.toString('hex'), '9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271')
        assert.equal(hdkey.privateKey, null)
        assert.equal(hdkey.publicKey.toString('hex'), '024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c')
        assert.equal(hdkey.identifier.toString('hex'), '26132fdbe7bf89cbc64cf8dafa3f9f88b8666220')
      })
    })
  })

  describe('> when signing', () => {
    it('should work', () => {
      const key = 'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j';
      const hdkey = HDKey.fromExtendedKey(key);

      const ma = Buffer.alloc(32, 0);
      const mb = Buffer.alloc(32, 8);
      const a = hdkey.sign(ma);
      const b = hdkey.sign(mb);
      assert.equal(a.toString('hex'), 'e0d98bcddb7bf13b572e784c4bb81cd80635f3e673c734331408eae670632dc272d9cfce8cf45095b6e4cde563cd98be424b4f7cd3c7ccc0b67f29e7cde1d0bf')
      assert.equal(b.toString('hex'), '9edf534835acdad2f0ee89985f4cdf875c4667ada0d307d1051a8a181bd2f11239e9e2a556e577fbcba95373e4ba0ca7693b7db93baa10a955e60c7060651028')
      assert.equal(hdkey.verify(ma, a), true)
      assert.equal(hdkey.verify(mb, b), true)
      assert.equal(hdkey.verify(Buffer.alloc(32), Buffer.alloc(64)), false)
      assert.equal(hdkey.verify(ma, b), false)
      assert.equal(hdkey.verify(mb, a), false)
      assert.equal(hdkey.verify(Buffer.alloc(99), a),true)
      assert.throws(() => {
        hdkey.verify(ma, Buffer.alloc(99))
      }, /signature length is invalid/)
    })
  })

  describe('> when deriving public key', () => {
    it('should work', () => {
      const key = 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8';
      const hdkey = HDKey.fromExtendedKey(key);

      const path = 'm/3353535/2223/0/99424/4/33';
      const derivedHDKey = hdkey.derive(path);

      const expected = 'xpub6J1f2fSKiRBhwvopsYEd9bA8HLAgCCiKLd7ADKsPDxQuEMqXxj7Z1mkVeTN8f4dSWDZK82XnXtwiyWkeRAnQgMnWC5r8Kf832sbW7VsbzNy';
      assert.equal(derivedHDKey.publicExtendedKey, expected)
    })
  })

  describe('> when private key integer is less than 32 bytes', () => {
    it('should work', () => {
      const seed = '000102030405060708090a0b0c0d0e0f';
      const masterKey = HDKey.fromMasterSeed(Buffer.from(seed, 'hex'));

      const newKey = masterKey.derive("m/44'/6'/4'");
      const expected = 'xprv9ysDM9WBTHXoaitjKrkW1P8C6CtZtSvA7nbQXKNzLwzhkGsCna8ceY2Xuv4NSXPJZ1SRRAoU6biJ26P1dikUepXzA8JxBYCkU1P1RjytVFh';
      assert.equal(newKey.privateExtendedKey, expected)
    })
  })

  describe('HARDENED_OFFSET', () => {
    it('should be set', () => {
      assert(HDKey.HARDENED_OFFSET)
    })
  })

  describe('> when private key has leading zeros', () => {
    it('will include leading zeros when hashing to derive child', () => {
      const key = 'xprv9s21ZrQH143K3ckY9DgU79uMTJkQRLdbCCVDh81SnxTgPzLLGax6uHeBULTtaEtcAvKjXfT7ZWtHzKjTpujMkUd9dDb8msDeAfnJxrgAYhr';
      const hdkey = HDKey.fromExtendedKey(key);
      assert.equal(hdkey.privateKey.toString('hex'), '00000055378cf5fafb56c711c674143f9b0ee82ab0ba2924f19b64f5ae7cdbfd')
      const derived = hdkey.derive("m/44'/0'/0'/0/0'");
      assert.equal(derived.privateKey.toString('hex'), '3da46554845f779a6f15bf32adfc3137e00096ecb00d9721f4c2985883b7a568')
    })
  })

  describe('> when private key is null', () => {
    it('privateExtendedKey should return null and not throw', () => {
      const seed = '000102030405060708090a0b0c0d0e0f';
      const masterKey = HDKey.fromMasterSeed(Buffer.from(seed, 'hex'));

      assert.ok(masterKey.privateExtendedKey, 'xpriv is truthy')
      masterKey._privateKey = null

      assert.doesNotThrow(() => {
        masterKey.privateExtendedKey
      })

      assert.ok(!masterKey.privateExtendedKey, 'xpriv is falsy')
    })
  })

  describe(' - when the path given to derive contains only the master extended key', () => {
    const hdKeyInstance = HDKey.fromMasterSeed(Buffer.from(fixtures.valid[0].seed, 'hex'))

    it('should return the same hdkey instance', () => {
      assert.equal(hdKeyInstance.derive('m'), hdKeyInstance)
      assert.equal(hdKeyInstance.derive('M'), hdKeyInstance)
      assert.equal(hdKeyInstance.derive("m'"), hdKeyInstance)
      assert.equal(hdKeyInstance.derive("M'"), hdKeyInstance)
    })
  })

  describe(' - when the path given to derive does not begin with master extended key', () => {
    it('should throw an error', () => {
      assert.throws(() => {
        HDKey.prototype.derive('123')
      }, /Path must start with "m" or "M"/)
    })
  })
})
