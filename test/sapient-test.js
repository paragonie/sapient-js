"use strict";

const expect = require('chai').expect;
const {
    HeaderMissingException,
    InvalidMessageException,
    SealingSecretKey,
    SharedAuthenticationKey,
    SharedEncryptionKey,
    SigningSecretKey,
    Sapient
} = require('../index');

describe('Sapient', function () {
    let request = {'method': 'POST','form': {'name': 'Josh'}, "resolveWithFullResponse": true};
    it('Sealed Requests (Asymmetric)', async function() {
        let alice = await SealingSecretKey.generate();
        let sealed = await Sapient.sealRequest(request, alice.getPublicKey());
        expect(sealed.body.length).to.be.equal(76);
        let opened = await Sapient.unsealFormRequest(sealed, alice);
        expect(JSON.stringify(request)).to.be.equal(JSON.stringify(opened));
    });

    it('Signed Requests (Asymmetric)', async function() {
        let alice = await SigningSecretKey.generate();

        let signed = await Sapient.signRequest(request, alice);

        // Valid signature
        expect(JSON.stringify(signed)).to.be.equal(
            JSON.stringify(
                await Sapient.verifySignedRequest(signed, alice.getPublicKey())
            )
        );

        // Missing signature
        try {
            await Sapient.verifySignedRequest(request, alice.getPublicKey());
            throw new Error("Expected exception was not thrown");
        } catch (e) {
            expect(e instanceof HeaderMissingException).to.be.equal(true);
        }

        // Invalid signature
        try {
            await Sapient.verifySignedRequest({
                'method': 'POST',
                'form': {'name': 'John'},
                'headers': signed.headers
            }, alice.getPublicKey());
            throw new Error("Expected exception was not thrown");
        } catch (e) {
            expect(e instanceof InvalidMessageException).to.be.equal(true);
        }
    });

    it('Authenticated Requests (Symmetric)', async function () {
        let key = await SharedAuthenticationKey.generate();
        let authed = await Sapient.authenticateRequestWithSharedKey(request, key);
        expect(JSON.stringify(authed)).to.be.equal(
            JSON.stringify(
                await Sapient.verifySymmetricAuthenticatedRequest(authed, key)
            )
        );
    });

    it('Encrypted Requests (Symmetric)', async function () {
        let key = await SharedEncryptionKey.generate();
        let encrypted = await Sapient.encryptRequestWithSharedKey(request, key);
        expect(encrypted.body.length).to.be.equal(68);
        let decrypted = await Sapient.decryptFormRequestWithSharedKey(encrypted, key);
        expect(JSON.stringify(request.form)).to.be.equal(JSON.stringify(decrypted.form));
    });
});
