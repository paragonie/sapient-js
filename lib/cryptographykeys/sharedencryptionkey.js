"use strict";

const CryptographyKey = require('../cryptographykey');
const { SodiumPlus } = require('sodium-plus');

module.exports = class SharedEncryptionKey extends CryptographyKey {
    /**
     * @param {Buffer} key
     */
    constructor(key) {
        if (key.length !== 32) {
            throw new Error("Key must be 32 bytes long");
        }
        super(key);
    }

    static async generate() {
        let sodium = await SodiumPlus.auto();
        return new SharedEncryptionKey(
            (await sodium.crypto_aead_xchacha20poly1305_ietf_keygen()).getBuffer()
        );
    }
};
