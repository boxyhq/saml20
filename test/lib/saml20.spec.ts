import * as saml20 from '../../lib/saml20';
import { expect } from 'chai';
import fs from 'fs';

const assertion = fs.readFileSync('./test/assets/saml20.validResponseSignedMessage.xml').toString();

const validateOpts = {
  thumbprint: 'e606eced42fa3abd0c5693456384f5931b174707',
  audience: 'http://sp.example.com/demo1/metadata.php',
  inResponseTo: 'ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685',
};

const validateOptsArray = [
  'e606eced42fa3abd0c5693456384f5931b174707',
  'http://sp.example.com/demo1/metadata.php',
  'ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685',
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
