"use strict";

const base64url = require('rfc4648').base64url;
const SealingPublicKey = require('./signingpublickey');
const SharedEncryptionKey = require('./sharedencryptionkey');
const {SodiumPlus, X25519SecretKey, X25519PublicKey} = require('sodium-plus');

let sodium;

module.exports = class SealingSecretKey extends X25519SecretKey {
    async wipeBuffer() {
        if (!sodium) sodium = await SodiumPlus.auto();
        await sodium.sodium_memzero(this.buffer);
    }

    /**
     * @param {string} str
     * @return {SealingSecretKey}
     */
    static fromString(str) {
        return new this(base64url.parse(str));
    }

    getString() {
        return base64url.stringify(this.key);
    }

    /**
     * @param {Buffer} key
     * @param {X25519PublicKey|null} pk
     */
    constructor(key, pk = null) {
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
        if (!sodium) sodium = await SodiumPlus.auto();
        if (!this.pk) {
            await this.deriveAndStorePublicKey();
        }
        if (serverSide) {
            return new SharedEncryptionKey(
                await sodium.crypto_generichash(
                    Buffer.concat([
                        sodium.crypto_scalarmult(this.key, publicKey),
                        publicKey,
                        this.getPublicKey()
                    ])
                )
            );
        } else {
            return new SharedEncryptionKey(
                await sodium.crypto_generichash(
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
        if (!sodium) sodium = await SodiumPlus.auto();
        let keypair = await sodium.crypto_box_keypair();
        return new SealingSecretKey(
            (await sodium.crypto_box_secretkey(keypair)).getBuffer(),
            await sodium.crypto_box_publickey(keypair)
        );
    }

    /**
     * Calculate the X25519 public key, store it in the pk property.
     *
     * @return {Promise<SealingSecretKey>}
     */
    async deriveAndStorePublicKey() {
        if (!sodium) sodium = await SodiumPlus.auto();
        this.pk = await sodium.crypto_box_publickey_from_secretkey(this.key);
        return this;
    }

    /**
     * @return {SealingPublicKey}
     */
    getPublicKey() {
        return this.pk;
    }
};
