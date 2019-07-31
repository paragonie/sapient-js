"use strict";

const CryptographyKey = require('../cryptographykey');
const SealingPublicKey = require('./signingpublickey');
const SharedEncryptionKey = require('./sharedencryptionkey');
const sodium = require('libsodium-wrappers');

module.exports = class SealingSecretKey extends CryptographyKey {
    /**
     * @param {Buffer} key
     * @param {Buffer|null} pk
     */
    constructor(key, pk = null) {
        if (key.length !== 32) {
            throw new Error("Key must be 32 bytes long");
        }
        super(key);
        if (pk) {
            this.pk = pk;
        } else {
            this.deriveAndStorePublicKey().then(() => {return});
        }
    }

    /**
     *
     * @param {SealingPublicKey} publicKey
     * @param {boolean} serverSide
     * @return {SharedEncryptionKey}
     */
    async deriveSharedEncryptionKey(publicKey, serverSide = false) {
        await sodium.ready;
        if (!this.pk) {
            await this.deriveAndStorePublicKey();
        }
        if (serverSide) {
            return new SharedEncryptionKey(
                sodium.crypto_generichash(
                    Buffer.concat([
                        sodium.crypto_scalarmult(this.key, publicKey),
                        publicKey,
                        this.getPublicKey()
                    ])
                )
            );
        } else {
            return new SharedEncryptionKey(
                sodium.crypto_generichash(
                    Buffer.concat([
                        sodium.crypto_scalarmult(this.key, publicKey),
                        this.getPublicKey(),
                        publicKey
                    ])
                )
            );
        }
    }

    static async generate() {
        await sodium.ready;
        let keypair = sodium.crypto_box_keypair();
        return new SealingSecretKey(keypair.privateKey, keypair.publicKey);
    }

    /**
     * Calculate the X25519 public key, store it in the pk property.
     *
     * @return {Promise<SealingSecretKey>}
     */
    async deriveAndStorePublicKey() {
        await sodium.ready;
        this.pk = sodium.crypto_box_publickey_from_secretkey(this.key);
        return this;
    }

    /**
     * @return {SealingPublicKey}
     */
    getPublicKey() {
        return new SealingPublicKey(this.pk);
    }
};
