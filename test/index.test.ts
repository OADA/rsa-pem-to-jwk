/*
 * Copyright 2014 Open Ag Data Alliance
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

import * as fs from 'fs';
import * as path from 'path';
import rsaPemToJwk from '../src';

describe('rsa-pem-to-jwk', () => {
  const privatePem = fs.readFileSync(path.join(__dirname, 'data', 'private.pem')).toString();
  const publicPem = fs.readFileSync(path.join(__dirname, 'data', 'public.pem')).toString();
  const expectedPublic = require('./data/expectedPublic.json');
  const expectedPrivate = require('./data/expectedPrivate.json');

  test('should fail for an invalid PEM', () => {
    var jwk = rsaPemToJwk('INVALID');

    expect(jwk).toBeUndefined();
  });

  test('should return a public JWK by default', () => {
    var jwk = rsaPemToJwk(publicPem);

    expect(jwk).toEqual(expectedPublic);
  });

  test('should return a private JWK by default', () => {
    var jwk = rsaPemToJwk(privatePem);

    expect(jwk).toEqual(expectedPrivate);
  });

  test('should return a public JWK with extra keys', () => {
    var jwk = rsaPemToJwk(publicPem, { use: 'sig' });

    expect(jwk).toEqual(Object.assign({}, expectedPublic, { use: 'sig' }));
  });

  test('should return a private JWK with extra keys', () => {
    var jwk = rsaPemToJwk(privatePem, { use: 'sig' });

    expect(jwk).toEqual(Object.assign({}, expectedPrivate, { use: 'sig' }));
  });

  test('should return a public JWK from a private PEM', () => {
    var jwk = rsaPemToJwk(privatePem, 'public');

    expect(jwk).toEqual(expectedPublic);
  });

  test('should return a public JWK with extra keys from a private PEM', () => {
    var jwk = rsaPemToJwk(privatePem, { use: 'sig' }, 'public');

    expect(jwk).toEqual(Object.assign({}, expectedPublic, { use: 'sig' }));
  });

  test('should fail to return a private JWK from a public PEM', () => {
    var jwk = rsaPemToJwk(publicPem, 'private');

    expect(jwk).toBeUndefined();
  });

  test('should fail to return a private JWK with extra keys from public PEM', () => {
    var jwk = rsaPemToJwk(publicPem, { use: 'sig' }, 'private');

    expect(jwk).toBeUndefined();
  });
});
