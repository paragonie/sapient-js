"use strict";

const base64url = require('rfc4648').base64url;
const sodium = require('libsodium-wrappers');

module.exports = class CryptographyKey {
    /**
     * @param {Buffer} key
     */
    constructor(key) {
        if (!Buffer.isBuffer(key)) {
            key = Buffer.from(key);
        }
        this.key = key;
    }

    async wipeBuffer() {
        await sodium.ready;
        sodium.memzero(this.key);
    }

    getBuffer() {
        return Buffer.concat([this.key]);
    }

    getString() {
        return base64url.stringify(this.key);
    }
};
