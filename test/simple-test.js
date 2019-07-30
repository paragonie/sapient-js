const expect = require('chai').expect;

const {
    SharedEncryptionKey,
    SealingSecretKey,
    Simple
} = require('../index');
const sodium = require('libsodium-wrappers');

describe('Simple', function () {
    it('encrypt / decrypt', async function () {
        await sodium.ready;
        let key = await SharedEncryptionKey.generate();

        let plaintext = "This is just a test message.";
        let cipher = await Simple.encrypt(plaintext, key);
        expect(cipher.length).to.be.equal(plaintext.length + 40);
        let decrypted = sodium.to_string(await Simple.decrypt(cipher, key));
        expect(plaintext).to.be.equal(decrypted);
    });

    it('key exchange', async function () {
        await sodium.ready;

        let alice = await SealingSecretKey.generate();
        let bob =  await SealingSecretKey.generate();

        let aliceToBob = await Simple.keyExchange(alice, await bob.getPublicKey(), false);
        let bobToAlice = await Simple.keyExchange(bob, await alice.getPublicKey(), true);

        expect(sodium.to_hex(aliceToBob)).to.be.equal(sodium.to_hex(bobToAlice));
    });

    it('seal / unseal', async function () {
        await sodium.ready;
        let alice = await SealingSecretKey.generate();

        let plaintext = "This is just a test message";
        let sealed = await Simple.seal(plaintext, alice.getPublicKey());
        let opened = await Simple.unseal(sealed, alice);

        expect(plaintext).to.be.equal(sodium.to_string(opened));
    });
});
