import * as saml20 from '../../lib/saml20';
import { expect } from 'chai';
import fs from 'fs';

const assertion = fs.readFileSync('./test/assets/saml20.rawResponse.xml').toString();

const validateOpts = {
  thumbprint: 'ecd00c7bafd40eed03e98646c9d5a802f39d4b07',
  audience: 'https://saml.boxyhq.com',
  inResponseTo: '_ec9ff74838da0a662a95',
};

const validateOptsArray = [
  'ecd00c7bafd40eed03e98646c9d5a802f39d4b07',
  'https://saml.boxyhq.com',
  '_ec9ff74838da0a662a95',
];

describe('saml20.ts', function () {
  it('parse assertion ok', function () {
    expect(saml20.default.parse(assertion)).to.be.ok;
  });

  it('parse assertion not ok', function () {
    try {
      saml20.default.parse('assertion');
    } catch (error) {
      console.log(error);
    }
  });

  it('ValidateAsync audience false', function () {
    expect(saml20.default.validateAudience(assertion, validateOpts)).to.be.false;
  });

  it('ValidateAsync assertion  not ok', function () {
    try {
      saml20.default.validateAudience('assertion', validateOpts);
    } catch (error) {
      console.log(error);
    }
  });

  it('ValidateAsync empty Array not ok', function () {
    try {
      saml20.default.validateAudience(assertion, []);
    } catch (error) {
      console.log(error);
    }
  });

  it('ValidateAsync empty Array ok', function () {
    try {
      saml20.default.validateAudience(assertion, validateOptsArray);
    } catch (error) {
      console.log(error);
    }
  });

  it('ValidateAsync not ok', function () {
    try {
      saml20.default.validateAudience('assertion', 'validateOpts');
    } catch (error) {
      console.log(error);
    }
  });

  it('validateExpiration ok', function () {
    expect(saml20.default.validateExpiration(assertion)).to.be.ok;
  });

  it('validateExpiration not ok', function () {
    try {
      saml20.default.validateExpiration('assertion');
    } catch (error) {
      console.log(error);
    }
  });
});
