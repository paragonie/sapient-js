const expect = require('chai').expect;

const {
    SharedEncryptionKey,
    SealingSecretKey,
    Simple
} = require('../index');
const {SodiumPlus} = require('sodium-plus');
let sodium;

describe('Simple', function () {
    it('encrypt / decrypt', async function () {
        if (!sodium) sodium = await SodiumPlus.auto();
        let key = await SharedEncryptionKey.generate();

        let plaintext = "This is just a test message.";
        let cipher = await Simple.encrypt(plaintext, key);
        expect(cipher.length).to.be.equal(plaintext.length + 40);
        let decrypted = await Simple.decrypt(cipher, key);
        expect(plaintext).to.be.equal(decrypted.toString('utf-8'));
    });

    it('key exchange', async function () {
        if (!sodium) sodium = await SodiumPlus.auto();

        let alice = await SealingSecretKey.generate();
        let bob =  await SealingSecretKey.generate();

        let aliceToBob = await Simple.keyExchange(alice, await bob.getPublicKey(), false);
        let bobToAlice = await Simple.keyExchange(bob, await alice.getPublicKey(), true);

        expect(aliceToBob.toString('hex')).to.be.equal(bobToAlice.toString('hex'));
    });

    it('seal / unseal', async function () {
        if (!sodium) sodium = await SodiumPlus.auto();
        let alice = await SealingSecretKey.generate();

        let plaintext = "This is just a test message";
        let sealed = await Simple.seal(plaintext, alice.getPublicKey());
        let opened = await Simple.unseal(sealed, alice);

        expect(plaintext).to.be.equal(opened.toString('utf-8'));
    });
});
