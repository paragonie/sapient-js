"use strict";

const CryptographyKey = require('../cryptographykey');
const {Ed25519PublicKey} = require('sodium-plus');
const base64url = require('rfc4648').base64url;
const arrayToBuffer = require('typedarray-to-buffer');

module.exports = class SigningPublicKey extends Ed25519PublicKey {
    /**
     * @param {string} str
     * @return {CryptographyKey}
     */
    static fromString(str) {
        return new this(arrayToBuffer(base64url.parse(str)));
    }

    getString() {
        return base64url.stringify(this.buffer);
    }
};
