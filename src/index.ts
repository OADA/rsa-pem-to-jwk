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

import rsaUnpack, { PrivateKey } from '@rexxars/rsa-unpack';

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
export default function rsaPemToJwk(
  pem: string,
  extraKeys: JwkExtraKeys = {},
  type: JwkKeyType = undefined
): PublicJwk | PrivateJwk | undefined {
  // Unpack the PEM
  var key = rsaUnpack(pem);
  if (key === undefined) {
    return undefined;
  }

  // Process parameters
  if (typeof extraKeys === 'string') {
    type = extraKeys as JwkKeyType;
    extraKeys = {};
  }
  type = type || ('privateExponent' in key ? 'private' : 'public');

  // Requested private JWK but gave a public PEM
  if (type === 'private' && !('privateExponent' in key)) {
    return undefined;
  }

  // Make the public exponent into a buffer of minimal size
  var expSize = Math.ceil(Math.log(key.publicExponent) / Math.log(256));
  var exp = new Buffer(expSize);
  var v = key.publicExponent;

  for (var i = expSize - 1; i >= 0; i--) {
    exp.writeUInt8(v % 256, i);
    v = Math.floor(v / 256);
  }

  // The public portion is always present
  var r = Object.assign({ kty: 'RSA' }, extraKeys, {
    n: base64url(key.modulus),
    e: base64url(exp),
  });

  // Add private
  if (type === 'private') {
    Object.assign(r, {
      d: base64url((key as PrivateKey).privateExponent),
      p: base64url((key as PrivateKey).prime1),
      q: base64url((key as PrivateKey).prime2),
      dp: base64url((key as PrivateKey).exponent1),
      dq: base64url((key as PrivateKey).exponent2),
      qi: base64url((key as PrivateKey).coefficient),
    });
  }

  return r;
}

// @ts-ignore
function base64url(b) {
  return b.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

export interface PublicJwk {
  n: string;
  e: string;
}

export type PrivateJwk = PublicJwk & {
  d: string;
  p: string;
  q: string;
  dp: string;
  dq: string;
  qi: string;
};

export type JwkKeyType = undefined | 'public' | 'private';
export type JwkExtraKeys = string | {};
