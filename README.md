# Sapient.js

[![Travis CI](https://travis-ci.org/paragonie/sapient.svg?branch=master)](https://travis-ci.org/paragonie/sapient)
[![npm version](https://img.shields.io/npm/v/sapient.svg)](https://npm.im/sapient)

**Sapient** secures your Node.js applications' server-to-server HTTP(S) traffic even in the wake of a
TLS security breakdown (compromised certificate authority, etc.).

Sapient allows you to quickly and easily add application-layer cryptography to your API requests
and responses.

----

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
        await Sapient.verifySignedRequest(request, sk.getPublicKey());
    } catch (e) {
        console.log(e.message);
    }
})();
```
