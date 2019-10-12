"use strict";

const SodiumPlus = require('sodium-plus').SodiumPlus;
const BaseClass = require('sodium-plus').CryptographyKey;
const base64url = require('rfc4648').base64url;
const arrayToBuffer = require('typedarray-to-buffer');

module.exports = class CryptographyKey extends BaseClass {
    async wipeBuffer() {
        let sodium = await SodiumPlus.auto();
        sodium.memzero(this.key);
    }

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
