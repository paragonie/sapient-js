"use strict";

const CryptographyKey = require('../cryptographykey');
const SigningPublicKey = require('./signingpublickey');
const {SodiumPlus, Ed25519SecretKey} = require('sodium-plus');

module.exports = class SigningSecretKey extends Ed25519SecretKey {

    static async generate() {
        let sodium = await SodiumPlus.auto();
        let keypair = await sodium.crypto_sign_keypair();
        return new SigningSecretKey(keypair.getBuffer().slice(0, 64));
    }

    getPublicKey() {
        return new SigningPublicKey(this.buffer.slice(32,64));
    }
};
