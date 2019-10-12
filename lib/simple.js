"use strict";
const { CryptographyKey, SodiumPlus } = require('sodium-plus');
const SharedEncryptionKey = require('./cryptographykeys/sharedencryptionkey');
const SealingPublicKey = require('./cryptographykeys/sealingpublickey');
const SealingSecretKey = require('./cryptographykeys/sealingsecretkey');

let sodium;

module.exports = class Simple {
    /**
     * Returns the sodium module after guaranteeing it has been initialized
     *
     * @return {Promise<SodiumPlus>}
     */
    static async getSodium() {
        return await SodiumPlus.auto();
    }

    /**
     * Simple authenticated encryption
     * XChaCha20-Poly1305
     *
     * @param {string|Buffer} plaintext
     * @param {SharedEncryptionKey} key
     * @return {Promise<Buffer>}
     */
    static async encrypt(plaintext, key) {
        if (!sodium) sodium = await Simple.getSodium();
        if (!(key instanceof SharedEncryptionKey)) {
            throw new TypeError();
        }
        let nonce = await sodium.randombytes_buf(24); // CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
        return Buffer.concat([
            nonce,
            await sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
                plaintext,
                nonce,
                key,
                nonce
            )
        ]);
    }

    /**
     * Simple authenticated decryption
     * XChaCha20-Poly1305
     *
     * @param {string|Buffer} plaintext
     * @param {SharedEncryptionKey} key
     * @return {Promise<Buffer>}
     */
    static async decrypt(plaintext, key) {
        if (!sodium) sodium = await Simple.getSodium();
        if (!(key instanceof SharedEncryptionKey)) {
            throw new TypeError();
        }
        let nonce = plaintext.slice(0, 24);
        return Buffer.from(
            await sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                plaintext.slice(24),
                nonce,
                key,
                nonce
            )
        );
    }

    /**
     * Like libsodium's crypto_kx() but supports an arbitrary output length
     * in the range (16 <= N <= 64).
     *
     * @param {SealingSecretKey} sk
     * @param {SealingPublicKey} pk
     * @param {boolean} serverSide
     * @param {number} length
     * @return {Buffer}
     */
    static async keyExchange(sk, pk, serverSide, length = 32) {
        if (!(sk instanceof SealingSecretKey)) {
            throw new TypeError();
        }
        if (!sodium) sodium = await Simple.getSodium();
        let suffix;
        if (serverSide) {
            suffix = Buffer.concat([pk.getBuffer(), sk.getPublicKey().getBuffer()]);
        } else {
            suffix = Buffer.concat([sk.getPublicKey().getBuffer(), pk.getBuffer()]);
        }
        return await sodium.crypto_generichash(
            Buffer.concat([
                (await sodium.crypto_scalarmult(sk, pk)).getBuffer(),
                suffix
            ]),
            null,
            length
        );
    }

    /**
     * Encrypt a message with a public key, so that it can only be decrypted
     * with the corresponding secret key.
     *
     * @param {string|Buffer} plaintext
     * @param {SealingPublicKey} publicKey
     * @return {Buffer}
     */
    static async seal(plaintext, publicKey) {
        if (!sodium) sodium = await Simple.getSodium();
        let ephemeral = await SealingSecretKey.generate();
        let ephPublic = ephemeral.getPublicKey().getBuffer();
        let sharedSecret = await Simple.keyExchange(ephemeral, publicKey, false, 56);
        let ciphertext = Buffer.from(
            await sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
                plaintext,
                sharedSecret.slice(32, 56),
                new CryptographyKey(sharedSecret.slice(0, 32)),
                ephPublic
            )
        );
        await ephemeral.wipeBuffer();
        await sodium.sodium_memzero(sharedSecret);
        return Buffer.concat([ephPublic, ciphertext]);
    }

    /**
     * Decrypt a message with your secret key.
     *
     * @param {Buffer} ciphertext
     * @param {SealingSecretKey} secretKey
     * @return {Buffer}
     */
    static async unseal(ciphertext, secretKey) {
        if (!sodium) sodium = await Simple.getSodium();
        let ephPublic = new SealingPublicKey(ciphertext.slice(0, 32));
        let sharedSecret = await Simple.keyExchange(secretKey, ephPublic, true, 56);
        let plaintext = Buffer.from(
            await sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                ciphertext.slice(32),
                sharedSecret.slice(32, 56),
                new CryptographyKey(sharedSecret.slice(0, 32)),
                ephPublic.getBuffer()
            )
        );
        await sodium.sodium_memzero(sharedSecret);
        return plaintext;
    }
};
