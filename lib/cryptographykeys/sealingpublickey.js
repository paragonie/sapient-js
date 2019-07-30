"use strict";

const CryptographyKey = require('../cryptographykey');

module.exports = class SealingPublicKey extends CryptographyKey {
    /**
     * @param {Buffer} key
     */
    constructor(key) {
        if (key.length !== 32) {
            throw new Error("Key must be 32 bytes long");
        }
        super(key);
    }
};
