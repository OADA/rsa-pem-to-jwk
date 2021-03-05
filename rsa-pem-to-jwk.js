/* Copyright 2014 Open Ag Data Alliance
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

function base64toArrayBuffer(base64) {
    return typeof atob !== 'undefined' ?
        Uint8Array.from(atob(base64), byte => byte.charCodeAt(0)) : // Browser API
        Uint8Array.from(Buffer.from(base64, 'base64')); // Node.js API
}

function arrayBufferToBase64(buffer) {
    return typeof btoa !== 'undefined' ?
        btoa(String.fromCharCode(...new Uint8Array(buffer))) : // Browser API
        Buffer.from(buffer).toString('base64'); // Node.js API
}

/*
 *  Parameters:
 *   pem - string of PEM encoded RSA key
 *   extraKeys - custom keys to be included in JWK
 *   type - 'public' for JWK of only the public portion of the key and
 *          'private' for a JWK of both the public and private portions
 *
 * Prototypes:
 *  - rsaPemToJwk('...', {...}, 'public');
 *  - rsaPemToJwk('...', 'private');
 *  - rsaPemToJwk('...', {...});
 */
module.exports = function rsaPemToJwk(pemKey, extraKeys, type) {
    // Process parameters
    if (typeof extraKeys === 'string') {
        type = extraKeys;
        extraKeys = {};
    }

    // Unpack the PEM
    pemKey = String(pemKey).trim().split("\n");

    // Check and remove RSA key header/footer
    let keyType = (/-----BEGIN RSA (PRIVATE|PUBLIC) KEY-----/.exec(pemKey.shift()) || [])[1];
    if (!keyType || !RegExp(`-----END RSA ${keyType} KEY-----`).exec(pemKey.pop())) {
        throw Error('Headers not supported.');
    }

    // Check requested JWK and given PEM types
    keyType = keyType.toLowerCase();
    if (!type) {
        type = keyType;
    } else if (type === 'private' && keyType === 'public') {
        throw Error(`RSA type mismatch: requested ${type}, given ${keyType}.`);
    }

    // PEM base64 to ArrayBuffer
    const derKey = new Uint8Array(base64toArrayBuffer(pemKey.join('')));

    // DER reading offset
    let offset = {
        private: derKey[1] & 0x80 ? derKey[1] - 0x80 + 5 : 7,
        public: derKey[1] & 0x80 ? derKey[1] - 0x80 + 2 : 2
    }[keyType];

    function read() {
        let s = derKey[offset + 1];

        if (s & 0x80) {
            let n = s - 0x80;
            s = new DataView(derKey.buffer)[ ['getUint8', 'getUint16'][n - 1] ](offset + 2);
            offset += n;
        }
        offset += 2;

        return derKey.slice(offset, offset += s);
    }

    const key = {
        modulus: read(),
        publicExponent: read(),
        privateExponent: read(),
        prime1: read(),
        prime2: read(),
        exponent1: read(),
        exponent2: read(),
        coefficient: read()
    };

    function base64Url(buffer) {
        return arrayBufferToBase64(buffer)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/g, '');
    }

    return {
        kty: 'RSA',
        ...extraKeys,
        // The public portion is always present
        n: base64Url(key.modulus),
        e: base64Url(key.publicExponent),
        // Read private part
        ...type === "private" && {
            d: base64Url(key.privateExponent),
            p: base64Url(key.prime1),
            q: base64Url(key.prime2),
            dp: base64Url(key.exponent1),
            dq: base64Url(key.exponent2),
            qi: base64Url(key.coefficient)
        }
    };
};
