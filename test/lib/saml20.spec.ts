import { default as saml20 } from '../../lib/saml20';
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

const assertion1 = {
  Conditions: {
    AudienceRestriction: {
      Audience: 'https://saml.boxyhq.com/f46e93394c5a51d36715d95d910872ac7372d4d9',
    },
  },
};

describe('saml20.ts', function () {
  it('parse assertion ok', function () {
    const value = saml20.parse(assertion);
    expect(value.audience).to.equal(undefined);
    expect(value.claims).to.empty;
    expect(value.issuer).to.equal(undefined);
    expect(value.sessionIndex).to.equal(undefined);
    expect(saml20.parse(assertion)).to.be.ok;
  });

  it('parse assertion not ok', function () {
    try {
      const value = saml20.parse('assertion');
      expect(value.audience).to.equal(undefined);
      expect(value.claims).to.empty;
      expect(value.issuer).to.equal(undefined);
      expect(value.sessionIndex).to.equal(undefined);
    } catch (error) {
      expect(error).to.be.ok;
    }
  });

  it('validateAudience false', function () {
    const value = saml20.validateAudience(assertion, validateOpts);
    expect(value).to.equal(false);
    expect(saml20.validateAudience(assertion, validateOpts)).to.be.false;
  });

  it('validateAudience assertion  not ok', function () {
    try {
      const value = saml20.validateAudience('assertion', validateOpts);
      expect(value).to.equal(false);
    } catch (error) {
      expect(error).to.be.ok;
    }
  });

  it('validateAudience empty Array not ok', function () {
    try {
      const value = saml20.validateAudience(assertion, []);
      expect(value).to.equal(false);
    } catch (error) {
      expect(error).to.be.ok;
    }
  });

  it('validateAudience empty Array ok', function () {
    try {
      const value = saml20.validateAudience(assertion, validateOptsArray);
      expect(value).to.equal(false);
    } catch (error) {
      expect(error).to.be.ok;
    }
  });

  it('validateAudience with Suffix ok', async function () {
    try {
      const value = saml20.validateAudience(assertion1, 'https://saml.boxyhq.com');
      expect(value).to.equal(true);
    } catch (error) {
      expect(error).to.be.ok;
    }
  });

  it('validateAudience with Suffix Array ok', async function () {
    try {
      const value = saml20.validateAudience(assertion1, [...validateOptsArray, 'https://saml.boxyhq.com']);
      expect(value).to.equal(true);
    } catch (error) {
      expect(error).to.be.ok;
    }
  });

  it('validateAudience with Suffix Array not ok', async function () {
    try {
      const value = saml20.validateAudience(assertion1, validateOptsArray);
      expect(value).to.equal(false);
    } catch (error) {
      expect(error).to.be.ok;
    }
  });

  it('validateAudience not ok', function () {
    try {
      const value = saml20.validateAudience('assertion', 'validateOpts');
      expect(value).to.equal(false);
    } catch (error) {
      expect(error).to.be.ok;
    }
  });

  it('validateExpiration ok', function () {
    const value = saml20.validateExpiration(assertion);
    expect(value).to.equal(true);
    expect(saml20.validateExpiration(assertion)).to.be.ok;
  });

  it('validateExpiration not ok', function () {
    try {
      const value = saml20.validateExpiration('assertion');
      expect(value).to.equal(true);
    } catch (error) {
      expect(error).to.be.ok;
    }
  });
});
