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
/*global describe, it */
/*jshint expr:true */
'use strict';

var fs = require('fs');
var path = require('path');
var expect = require('chai').expect;
var objectAssign = require('object-assign');

var rsaPemToJwk = require('../rsa-pem-to-jwk');

describe('rsa-pem-to-jwk', function() {
  var pem = fs.readFileSync(path.join(__dirname, 'data', 'input.pem'));
  var expectedPublic = require('./data/expectedPublic.json');
  var expectedPrivate = require('./data/expectedPrivate.json');

  it('should fail with invalid PEM', function() {
    var jwk = rsaPemToJwk('INVALID');

    expect(jwk).to.be.undefined;
  });

  it('should output a public key JWK by default', function() {
    var jwk = rsaPemToJwk(pem);

    expect(jwk).to.eql(expectedPublic);
  });

  it('should output a public key JWK with extra keys', function() {
    var jwk = rsaPemToJwk(pem, {use: 'sig'});

    expect(jwk).to.eql(objectAssign({}, expectedPublic, {use: 'sig'}));
  });

  it('should output a private key JWK', function() {
    var jwk = rsaPemToJwk(pem, 'private');

    expect(jwk).to.eql(expectedPrivate);
  });

  it('should output a private key JWK with extra keys', function() {
    var jwk = rsaPemToJwk(pem, {use: 'sig'}, 'private');

    expect(jwk).to.eql(objectAssign({}, expectedPrivate, {use: 'sig'}));
  });
});
