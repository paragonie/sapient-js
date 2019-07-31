"use strict";

const base64url = require('rfc4648').base64url;
const HeaderMissingException = require('./exception/headermissingexception');
const InvalidMessageException = require('./exception/invalidmessageexception');
const queryString = require('query-string');
const SealingPublicKey = require('./cryptographykeys/sealingpublickey');
const SealingSecretKey = require('./cryptographykeys/sealingsecretkey');
const SharedAuthenticationKey = require('./cryptographykeys/sharedauthenticationkey');
const SharedEncryptionKey = require('./cryptographykeys/sharedencryptionkey');
const SigningPublicKey = require('./cryptographykeys/signingpublickey');
const SigningSecretKey = require('./cryptographykeys/signingsecretkey');
const Simple = require('./simple');
// const _sodium = require('libsodium-wrappers');

const HEADER_AUTH_NAME = 'Body-HMAC-SHA512256';
const HEADER_SIGNATURE_NAME = 'Body-Signature-Ed25519';

module.exports = class SapientCore {

    /**
     * @param {Object} request
     * @param {SharedAuthenticationKey} key
     */
    static async authenticateRequestWithSharedKey(request, key) {
        let sodium = await Simple.getSodium();
        let request2 = Object.assign({}, request);
        if (typeof request2.headers === 'undefined') {
            request2.headers = {};
        }
        let mac = sodium.crypto_auth(
            await SapientCore.serializeBody(request),
            key.getBuffer()
        );
        request2.headers[HEADER_AUTH_NAME] = base64url.stringify(mac);
        request2.resolveWithFullResponse = true;
        return request2;
    }

    /**
     *
     * @param {Object} request
     * @param {SharedEncryptionKey} key
     * @return {Object}
     */
    static async decryptRequestWithSharedKey(request, key) {
        let request2 = Object.assign({}, request);
        request2.body = await Simple.decrypt(
            base64url.parse(request.body),
            key
        );
        request2.resolveWithFullResponse = true;
        return request2;
    }

    /**
     *
     * @param {Object} request
     * @param {SharedEncryptionKey} key
     * @return {Object}
     */
    static async encryptRequestWithSharedKey(request, key) {
        let request2 = Object.assign({}, request);
        request2.body = base64url.stringify(
            await Simple.encrypt(
                await SapientCore.serializeBody(request),
                key
            )
        );
        request2.resolveWithFullResponse = true;
        return request2;
    }

    /**
     * @param {Object} request
     * @param {SealingPublicKey} pk
     * @return {Object}
     */
    static async sealRequest(request, pk) {
        let request2 = Object.assign({}, request);
        request2.body = base64url.stringify(
            await Simple.seal(
                await SapientCore.serializeBody(request),
                pk
            )
        );
        request2.resolveWithFullResponse = true;
        return request2;
    }

    /**
     * @param {Object} request
     * @param {SealingSecretKey} sk
     * @return {Object}
     */
    static async unsealRequest(request, sk) {
        let request2 = Object.assign({}, request);
        request2.body = await Simple.unseal(
            base64url.parse(request.body),
            sk
        );
        request2.resolveWithFullResponse = true;
        return request2;
    }

    /**
     *
     * @param {Object} request
     * @param {SigningSecretKey} sk
     * @return {Object}
     */
    static async signRequest(request, sk) {
        let sodium = await Simple.getSodium();
        let request2 = Object.assign({}, request);
        if (typeof (request2.headers) === 'undefined') {
            request2.headers = {};
        }
        request2.headers[HEADER_SIGNATURE_NAME] = base64url.stringify(
            sodium.crypto_sign_detached(
                await SapientCore.serializeBody(request),
                sk.getBuffer()
            )
        );
        request2.resolveWithFullResponse = true;
        return request2;
    }

    /**
     * Verifies the signature contained in the Body-Signature-Ed25519 header
     * is valid for the HTTP Request body provided. Will either return the
     * request given, or throw an InvalidMessageException if the signature
     * is invalid. Will also throw a HeaderMissingException is there is no
     * Body-Signature-Ed25519 header.
     *
     * @param {Object} request
     * @param {SigningPublicKey} pk
     * @return {Object}
     */
    static async verifySignedRequest(request, pk) {
        let sodium = await Simple.getSodium();
        let request2 = Object.assign({}, request);
        if (typeof (request2.headers) === 'undefined') {
            throw new HeaderMissingException('No headers to verify');
        }
        let valid = false;
        let body = await SapientCore.serializeBody(request2);
        for (let h in request2.headers) {
            if (request2.headers.hasOwnProperty(h)) {
                if (h.toLowerCase() === HEADER_SIGNATURE_NAME.toLowerCase()) {
                    // This header, when cast to lowercase, matches.
                    if (typeof(request2.headers[h]) === 'string') {
                        // Single header check
                        valid = valid || sodium.crypto_sign_verify_detached(
                            base64url.parse(request2.headers[h]),
                            body,
                            pk.getBuffer()
                        );
                    } else {
                        // Multiple header checks
                        for (let head of request2.headers[h]) {
                            valid = valid || sodium.crypto_sign_verify_detached(
                                base64url.parse(head),
                                body,
                                pk.getBuffer()
                            );
                            if (valid) {
                                break;
                            }
                        }
                    }
                    if (valid) {
                        break;
                    }
                }
            }
        }
        if (!valid) {
            throw new InvalidMessageException(`No valid ${HEADER_SIGNATURE_NAME} header found`);
        }
        request2.body = body;
        request2.resolveWithFullResponse = true;
        return request2;
    }

    /**
     * @param {Object} request
     * @param {SharedAuthenticationKey} key
     * @return {Object}
     */
    static async verifySymmetricAuthenticatedRequest(request, key) {
        let sodium = await Simple.getSodium();
        let request2 = Object.assign({}, request);
        if (typeof (request2.headers) === 'undefined') {
            throw new HeaderMissingException('No headers to verify');
        }
        let valid = false;
        let body = await SapientCore.serializeBody(request);
        for (let h in request2.headers) {
            if (request2.headers.hasOwnProperty(h)) {
                if (h.toLowerCase() === HEADER_AUTH_NAME.toLowerCase()) {
                    // This header, when cast to lowercase, matches.
                    if (typeof(request2.headers[h]) === 'string') {
                        // Single header check
                        valid = valid || sodium.crypto_auth_verify(
                            base64url.parse(request2.headers[h]),
                            body,
                            key.getBuffer()
                        );
                    } else {
                        // Multiple header checks
                        for (let head of request2.headers[h]) {
                            valid = valid || sodium.crypto_auth_verify(
                                base64url.parse(head),
                                body,
                                key.getBuffer()
                            );
                            if (valid) {
                                break;
                            }
                        }
                    }
                    if (valid) {
                        break;
                    }
                }
            }
        }
        if (!valid) {
            throw new InvalidMessageException(`No valid ${HEADER_SIGNATURE_NAME} header found`);
        }
        request2.body = body;
        request2.resolveWithFullResponse = true;
        return request2;
    }

    /**
     *
     * @param {Object} obj
     * @param {string|null} prefix
     * @return {string}
     * @link https://stackoverflow.com/a/1714899
     */
    static objectToRequestParams(obj, prefix = null) {
        let str = [];
        for (let p in obj) {
            if (obj.hasOwnProperty(p)) {
                let k = prefix ? prefix + "[" + p + "]" : p,
                    v = obj[p];
                str.push((v !== null && typeof v === "object") ?
                    SapientCore.objectToRequestParams(v, k) :
                    encodeURIComponent(k) + "=" + encodeURIComponent(v));
            }
        }
        return str.join("&");
    }

    /**
     *
     * @param {Object} httpMessage
     * @return {Promise<string>}
     */
    static async serializeBody(httpMessage) {
        if (typeof httpMessage.json !== 'undefined') {
            if (httpMessage.json) {
                return JSON.stringify(httpMessage.body);
            }
        }
        if (typeof httpMessage.body === 'string') {
            if (httpMessage.body) {
                return httpMessage.body;
            }
        }
        if (typeof httpMessage.form !== 'undefined') {
            return SapientCore.objectToRequestParams(httpMessage.form);
        }
        return '';
    }

    /**
     * @param {Object} response
     * @param {SharedAuthenticationKey} key
     * @return {Object}
     */
    static async authenticateResponseWithSharedKey(response, key) {
        return await SapientCore.authenticateRequestWithSharedKey(response, key);
    }

    /**
     * @param {Object} response
     * @param {SharedEncryptionKey} key
     * @return {Object}
     */
    static async decryptResponseWithSharedKey(response, key) {
        return await SapientCore.decryptRequestWithSharedKey(response, key);
    }

    /**
     * @param {Object} response
     * @param {SharedEncryptionKey} key
     * @return {Object}
     */
    static async encryptResponseWithSharedKey(response, key) {
        return await SapientCore.encryptRequestWithSharedKey(response, key);
    }

    /**
     *
     * @param {Object} response
     * @param {SealingPublicKey} pk
     * @return {Object}
     */
    static async sealResponse(response, pk) {
        return await SapientCore.sealRequest(response, pk);
    }

    /**
     *
     * @param {Object} response
     * @param {SealingSecretKey} sk
     * @return {Object}
     */
    static async unsealResponse(response, sk) {
        return await SapientCore.unsealRequest(response, sk);
    }

    /**
     * @param {Object} response
     * @param {SigningSecretKey} sk
     * @return {Object}
     */
    static async signResponse(response, sk) {
        return await SapientCore.signRequest(response, sk);
    }

    /**
     * @param {Object} response
     * @param {SigningPublicKey} pk
     * @return {Object}
     */
    static async verifySignedResponse(response, pk) {
        return await SapientCore.verifySignedRequest(response, pk);
    }

    /**
     * @param {Object} response
     * @param {SharedAuthenticationKey} key
     * @return {Object}
     */
    static async verifySymmetricAuthenticatedResponse(response, key) {
        return await SapientCore.verifySymmetricAuthenticatedRequest(response, key);
    }
};
