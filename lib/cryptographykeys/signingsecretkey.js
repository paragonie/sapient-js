"use strict";

const CryptographyKey = require('../cryptographykey');
const SigningPublicKey = require('./signingpublickey');
const sodium = require('libsodium-wrappers');

module.exports = class SigningSecretKey extends CryptographyKey {
    /**
     * @param {Buffer} key
     */
    constructor(key) {
        if (key.length !== 64) {
            throw new Error("Key must be 64 bytes long");
        }
        super(key);
    }

    static async generate() {
        await sodium.ready;
        let keypair = sodium.crypto_sign_keypair();
        return new SigningSecretKey(keypair.privateKey);
    }

    getPublicKey() {
        return new SigningPublicKey(this.key.slice(32,64));
    }
};
