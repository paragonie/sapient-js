# Sapient.js

[![Travis CI](https://travis-ci.org/paragonie/sapient-js.svg?branch=master)](https://travis-ci.org/paragonie/sapient-js)
[![npm version](https://img.shields.io/npm/v/sapient.svg)](https://npm.im/sapient)

**Sapient** secures your Node.js applications' server-to-server HTTP(S) traffic even in the wake of a
TLS security breakdown (compromised certificate authority, etc.).

Sapient allows you to quickly and easily add application-layer cryptography to your API requests
and responses.

## Features at a Glance

* Secure APIs:
  * Shared-key encryption
    * XChaCha20-Poly1305
  * Shared-key authentication
    * HMAC-SHA512-256
  * Anonymous public-key encryption
    * X25519 + BLAKE2b + XChaCha20-Poly1305
  * Public-key digital signatures
    * Ed25519
* Digital signatures and authentication are backwards-compatible
  with unsigned JSON API clients and servers
  * The signaure and authentication tag will go into HTTP headers,
    rather than the request/response body.

# Installing Sapient

```terminal
npm install --save sapient
```

## Basic Usage

See the [request-promise](https://www.npmjs.com/package/request-promise)
documentation.

To use Sapient, you'll simply need to preprocess your `options` objects.

```javascript
const rp = require('request-promise-native');
const {Sapient, SigningSecretKey} = require('sapient');

(async function () {
    let sk = await SigningSecretKey.generate();
    let request = {
        'method': 'POST',
        'uri': 'https://example.com',
        'form': {
            'important': 'some value that needs integrity',
            'test': 12345,
            'now': '2019-07-31T09:00:00+00:00'
        }
    };
    let response = await rp(await Sapient.signFormRequest(request, sk));
    console.log(response.statusCode);
    try {
        await Sapient.verifySignedResponse(response, sk.getPublicKey());
    } catch (e) {
        console.log(e.message);
    }
})();
```

### Real World Example

This code will fetch data from [the PHP Chronicle](https://php-chronicle.pie-hosted.com),
verify the signature, return an object representing the JSON data that we authenticated.

```javascript
const rp = require('request-promise-native');
const {Sapient, SigningPublicKey} = require('sapient');

(async function () {
    let publicKey = SigningPublicKey.fromString(
        'MoavD16iqe9-QVhIy-ewD4DMp0QRH-drKfwhfeDAUG0='
    );
    let request = {
        'method': 'GET',
        'uri': 'https://php-chronicle.pie-hosted.com/chronicle/lookup/WQG3tH3CiLHg_upN0ABhKiYWOGwH3n9l4pM04bXwG54=',
        'resolveWithFullResponse': true
    };
    let response = await rp(request);
    console.log(await Sapient.decodeSignedJsonResponse(response, publicKey));
})();
```

This should result in the following (except with differing timestamps):
```
{ version: '1.1.x',
  datetime: '2019-07-31T03:37:48-04:00',
  status: 'OK',
  results: 
   [ { contents: '{\n    "repository": "paragonie\\/certainty",\n    "sha256": "cb2eca3fbfa232c9e3874e3852d43b33589f27face98eef10242a853d83a437a",\n    "signature": "d368533011b7e9eb09d1cc3a78faef70adcd1188aaee7a47698e0783339275b9b506a982c98dee119969c599581275f76733e0c2f96380405faed1d8678a0302",\n    "time": "2019-05-15T16:26:42-04:00"\n}',
       prevhash: '1RrlFkZRs6Srb9W2cNh-cGAzk5bkd9sVEes6ZShJ-ZA=',
       currhash: '8wL2OsihjC2ihOfyjqs2YwvZbry11veuWucqjhz4f6Y=',
       summaryhash: 'WQG3tH3CiLHg_upN0ABhKiYWOGwH3n9l4pM04bXwG54=',
       created: '2019-05-15T16:26:45-04:00',
       publickey: 'mPLfrUEV_qnwlsNUhbO_ILBulKysO3rPYYWqWAYCA0I=',
       signature: 'W8OKNuUa8Bma0TpKWmYXxFdyvyuPaq87hvcD6VIwQgfxFowSPM5L_6q7p4FGcXDQtxP41qKHf-ANEfgxOqztAw==' } ] } 
```

## Things that Use Sapient

* [Chronicle](https://github.com/paragonie/chronicle)
