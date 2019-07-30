"use strict";
const _sodium = require('libsodium-wrappers');
const SharedEncryptionKey = require('./cryptographykeys/sharedencryptionkey');
const SealingPublicKey = require('./cryptographykeys/sealingpublickey');
const SealingSecretKey = require('./cryptographykeys/sealingsecretkey');

module.exports = class Simple {
    /**
     * Returns the sodium module after guaranteeing it has been initialized
     *
     * @return {Promise<sodium>}
     */
    static async getSodium() {
        await _sodium.ready;
        return _sodium;
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
        let sodium = await Simple.getSodium();
        if (!(key instanceof SharedEncryptionKey)) {
            throw new TypeError();
        }
        let nonce = sodium.randombytes_buf(24); // CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
        return Buffer.concat([
            nonce,
            sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
                plaintext,
                nonce,
                null,
                nonce,
                key.getBuffer()
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
        let sodium = await Simple.getSodium();
        if (!(key instanceof SharedEncryptionKey)) {
            throw new TypeError();
        }
        let nonce = plaintext.slice(0, 24);
        return Buffer.from(
            sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                null,
                plaintext.slice(24),
                nonce,
                nonce,
                key.getBuffer()
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
        let sodium = await Simple.getSodium();
        let suffix;
        if (serverSide) {
            suffix = Buffer.concat([pk.getBuffer(), sk.getPublicKey().getBuffer()]);
        } else {
            suffix = Buffer.concat([sk.getPublicKey().getBuffer(), pk.getBuffer()]);
        }
        return sodium.crypto_generichash(
            length,
            Buffer.concat([sodium.crypto_scalarmult(sk.getBuffer(), pk.getBuffer()), suffix])
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
        let sodium = await Simple.getSodium();
        let ephemeral = await SealingSecretKey.generate();
        let ephPublic = ephemeral.getPublicKey().getBuffer();
        let sharedSecret = await Simple.keyExchange(ephemeral, publicKey, false, 56);
        let ciphertext = Buffer.from(
            sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
                plaintext,
                ephPublic,
                null,
                sharedSecret.slice(32, 56),
                sharedSecret.slice(0, 32)
            )
        );
        await ephemeral.wipeBuffer();
        await sodium.memzero(sharedSecret);
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
        let sodium = await Simple.getSodium();
        let ephPublic = new SealingPublicKey(ciphertext.slice(0, 32));
        let sharedSecret = await Simple.keyExchange(secretKey, ephPublic, true, 56);
        let plaintext = Buffer.from(
            sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                null,
                ciphertext.slice(32),
                ephPublic.getBuffer(),
                sharedSecret.slice(32, 56),
                sharedSecret.slice(0, 32)
            )
        );
        await sodium.memzero(sharedSecret);
        return plaintext;
    }
};
