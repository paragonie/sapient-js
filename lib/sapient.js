"use strict";

const queryString = require('query-string');
const SealingSecretKey = require('./cryptographykeys/sealingsecretkey');
const SharedAuthenticationKey = require('./cryptographykeys/sharedauthenticationkey');
const SharedEncryptionKey = require('./cryptographykeys/sharedencryptionkey');
const SigningPublicKey = require('./cryptographykeys/signingpublickey');
const SapientCore = require('./sapient-core');

module.exports = class Sapient extends SapientCore {
    /**
     * Verify the BODY-HMAC-SHA512256 header, and then decode the HTTP
     * Request body into an array (assuming the body is a valid form-encoded string).
     *
     * @param {Object} request
     * @param {SharedAuthenticationKey} key
     * @return {Object}
     */
    static async decodeSymmetricAuthenticatedFormRequest(request, key) {
        let authenticated = await SapientCore.verifySymmetricAuthenticatedRequest(request, key);
        authenticated.form = queryString.parse(authenticated.body.toString());
        delete authenticated.body;
        return authenticated;
    }

    /**
     * Verify the BODY-HMAC-SHA512256 header, and then decode the HTTP
     * Response body into an array (assuming the body is a valid form-encoded string).
     *
     * @param {Object} response
     * @param {SharedAuthenticationKey} key
     * @return {Object}
     */
    static async decodeSymmetricAuthenticatedFormResponse(response, key) {
        let authenticated = await SapientCore.verifySymmetricAuthenticatedResponse(response, key);
        authenticated.form = queryString.parse(authenticated.body.toString());
        delete authenticated.body;
        return authenticated;
    }

    /**
     * Verify the BODY-HMAC-SHA512256 header, and then decode the HTTP
     * Request body into an array (assuming the body is a valid JSON string).
     *
     * @param {Object} request
     * @param {SharedAuthenticationKey} key
     * @return {Object}
     */
    static async decodeSymmetricAuthenticatedJsonRequest(request, key) {
        return JSON.parse(await SapientCore.verifySymmetricAuthenticatedRequest(request, key).body);
    }

    /**
     * Verify the BODY-HMAC-SHA512256 header, and then decode the HTTP
     * Response body into an array (assuming the body is a valid JSON string).
     *
     * @param {Object} response
     * @param {SharedAuthenticationKey} key
     * @return {Object}
     */
    static async decodeSymmetricAuthenticatedJsonResponse(response, key) {
        return JSON.parse(await SapientCore.verifySymmetricAuthenticatedResponse(response, key).body);
    }

    /**
     * Verify the Body-Signature-Ed25519 header, and then decode the HTTP
     * Request body into an array (assuming the body is a valid form-encoded string).
     *
     * @param {Object} request
     * @param {SigningPublicKey} pk
     * @return {Object}
     */
    static async decodeSignedFormRequest(request, pk) {
        let authenticated = await SapientCore.verifySignedRequest(request, pk);
        authenticated.form = queryString.parse(authenticated.body.toString());
        delete authenticated.body;
        return authenticated;
    }

    /**
     * Verify the Body-Signature-Ed25519 header, and then decode the HTTP
     * Response body into an array (assuming the body is a valid form-encoded string).
     *
     * @param {Object} response
     * @param {SigningPublicKey} pk
     * @return {Object}
     */
    static async decodeSignedFormResponse(response, pk) {
        let authenticated = await SapientCore.verifySignedResponse(response, pk);
        authenticated.form = queryString.parse(authenticated.body.toString());
        delete authenticated.body;
        return authenticated;
    }

    /**
     * Verify the Body-Signature-Ed25519 header, and then decode the HTTP
     * Request body into an array (assuming the body is a valid JSON string).
     *
     * @param {Object} request
     * @param {SigningPublicKey} pk
     * @return {Object}
     */
    static async decodeSignedJsonRequest(request, pk) {
        return JSON.parse(await SapientCore.verifySignedRequest(request, pk).body);
    }

    /**
     * Verify the Body-Signature-Ed25519 header, and then decode the HTTP
     * Response body into an array (assuming the body is a valid JSON string).
     *
     * @param {Object} response
     * @param {SigningPublicKey} pk
     * @return {Object}
     */
    static async decodeSignedJsonResponse(response, pk) {
        return JSON.parse(await SapientCore.verifySignedResponse(response, pk).body);
    }

    /**
     * Decrypt an HTTP request with a pre-shared key, then decode into an
     * array (assuming the body is a valid form-encoded string).
     *
     * @param {Object} request
     * @param {SharedEncryptionKey} key
     * @return {Object}
     */
    static async decryptFormRequestWithSharedKey(request, key) {
        let decrypted = await SapientCore.decryptRequestWithSharedKey(request, key);
        decrypted.form = queryString.parse(decrypted.body.toString());
        delete decrypted.body;
        return decrypted;
    }

    /**
     * Decrypt an HTTP response with a pre-shared key, then decode into an
     * array (assuming the body is a valid form-encoded string).
     *
     * @param {Object} response
     * @param {SharedEncryptionKey} key
     * @return {Object}
     */
    static async decryptFormResponseWithSharedKey(response, key) {
        let decrypted = await SapientCore.decryptResponseWithSharedKey(response, key);
        decrypted.form = queryString.parse(decrypted.body.toString());
        delete decrypted.body;
        return decrypted;
    }

    /**
     * Decrypt an HTTP request with a pre-shared key, then decode into an
     * array (assuming the body is a valid JSON string).
     *
     * @param {Object} request
     * @param {SharedEncryptionKey} key
     * @return {Object}
     */
    static async decryptJsonRequestWithSharedKey(request, key) {
        return JSON.parse(await SapientCore.decryptRequestWithSharedKey(request, key).body);
    }

    /**
     * Decrypt an HTTP response with a pre-shared key, then decode into an
     * array (assuming the body is a valid JSON string).
     *
     * @param {Object} response
     * @param {SharedEncryptionKey} key
     * @return {Object}
     */
    static async decryptJsonResponseWithSharedKey(response, key) {
        return JSON.parse(await SapientCore.decryptResponseWithSharedKey(response, key).body);
    }

    /**
     * Decrypt a message with your secret key, that had been encrypted with
     * your public key by the other endpoint, then decode into an array.
     *
     * @param {Object} request
     * @param {SealingSecretKey} sk
     * @return {Object}
     */
    static async unsealFormRequest(request, sk) {
        let unsealed = await SapientCore.unsealRequest(request, sk);
        unsealed.form = queryString.parse(unsealed.body.toString());
        delete unsealed.body;
        return unsealed;
    }

    /**
     * Decrypt a message with your secret key, that had been encrypted with
     * your public key by the other endpoint, then decode into an array.
     *
     * @param {Object} response
     * @param {SealingSecretKey} sk
     * @return {Object}
     */
    static async unsealFormResponse(response, sk) {
        let unsealed = await SapientCore.unsealResponse(response, sk);
        unsealed.form = queryString.parse(unsealed.body.toString());
        delete unsealed.body;
        return unsealed;
    }

    /**
     * Decrypt a message with your secret key, that had been encrypted with
     * your public key by the other endpoint, then decode into an array.
     *
     * @param {Object} request
     * @param {SealingSecretKey} sk
     * @return {Object}
     */
    static async unsealJsonRequest(request, sk) {
        return JSON.parse(await SapientCore.unsealRequest(request, sk).body);
    }

    /**
     * Decrypt a message with your secret key, that had been encrypted with
     * your public key by the other endpoint, then decode into an array.
     *
     * @param {Object} response
     * @param {SealingSecretKey} sk
     * @return {Object}
     */
    static async unsealJsonResponse(response, sk) {
        return JSON.parse(await SapientCore.unsealResponse(response, sk).body);
    }

    /**
     * @param {Object} response
     * @param {SharedAuthenticationKey} key
     * @return {Object}
     */
    static async authenticateFormRequestWithSharedKey(response, key) {
        return await SapientCore.authenticateRequestWithSharedKey(response, key);
    }

    /**
     * @param {Object} response
     * @param {SharedAuthenticationKey} key
     * @return {Object}
     */
    static async authenticateJsonRequestWithSharedKey(response, key) {
        return await SapientCore.authenticateRequestWithSharedKey(response, key);
    }
    /**
     * @param {Object} response
     * @param {SharedEncryptionKey} key
     * @return {Object}
     */
    static async encryptFormRequestWithSharedKey(response, key) {
        return await SapientCore.encryptRequestWithSharedKey(response, key);
    }

    /**
     * @param {Object} response
     * @param {SharedEncryptionKey} key
     * @return {Object}
     */
    static async encryptJsonRequestWithSharedKey(response, key) {
        return await SapientCore.encryptRequestWithSharedKey(response, key);
    }

    /**
     * @param {Object} response
     * @param {SharedEncryptionKey} key
     * @return {Object}
     */
    static async encryptFormResponseWithSharedKey(response, key) {
        return await SapientCore.encryptRequestWithSharedKey(response, key);
    }

    /**
     * @param {Object} response
     * @param {SharedEncryptionKey} key
     * @return {Object}
     */
    static async encryptJsonResponseWithSharedKey(response, key) {
        return await SapientCore.encryptRequestWithSharedKey(response, key);
    }

    /**
     * @param {Object} response
     * @param {SealingPublicKey} pk
     * @return {Object}
     */
    static async sealFormRequest(response, pk) {
        return await SapientCore.sealRequest(response, pk);
    }

    /**
     * @param {Object} response
     * @param {SealingPublicKey} pk
     * @return {Object}
     */
    static async sealFormResponse(response, pk) {
        return await SapientCore.sealRequest(response, pk);
    }

    /**
     * @param {Object} response
     * @param {SealingPublicKey} pk
     * @return {Object}
     */
    static async sealJsonRequest(response, pk) {
        return await SapientCore.sealRequest(response, pk);
    }

    /**
     * @param {Object} response
     * @param {SealingPublicKey} pk
     * @return {Object}
     */
    static async sealJsonResponse(response, pk) {
        return await SapientCore.sealRequest(response, pk);
    }

    /**
     * @param {Object} request
     * @param {SigningSecretKey} sk
     * @return {Object}
     */
    static async signFormRequest(request, sk) {
        return await SapientCore.signRequest(request, sk);
    }

    /**
     * @param {Object} response
     * @param {SigningSecretKey} sk
     * @return {Object}
     */
    static async signFormResponse(response, sk) {
        return await SapientCore.signRequest(response, sk);
    }

    /**
     * @param {Object} request
     * @param {SigningSecretKey} sk
     * @return {Object}
     */
    static async signJsonRequest(request, sk) {
        return await SapientCore.signRequest(request, sk);
    }

    /**
     * @param {Object} response
     * @param {SigningSecretKey} sk
     * @return {Object}
     */
    static async signJsonResponse(response, sk) {
        return await SapientCore.signRequest(response, sk);
    }
};
