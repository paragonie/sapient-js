"use strict";
const expect = require('chai').expect;
const {
    SharedEncryptionKey,
    SigningPublicKey
} = require('../index');

describe('CryptographyKey', function () {
    it('should serialize from string', async function () {
        let encoded = 'MoavD16iqe9-QVhIy-ewD4DMp0QRH-drKfwhfeDAUG0=';
        let pk = SigningPublicKey.fromString(encoded);
        expect(encoded).to.be.equal(pk.getString());
    });

    it('should deserialize into an identical object', async function () {
        let key = await SharedEncryptionKey.generate();
        let encoded = key.getString();
        let k2 = SharedEncryptionKey.fromString(encoded);

        expect(
            key.getBuffer().toString('hex')
        ).to.be.equal(
            k2.getBuffer().toString('hex')
        );
    });
});
