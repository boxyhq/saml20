import { parse, validate } from '../../lib/response';
import { expect } from 'chai';
import fs from 'fs';

const rawResponse = fs.readFileSync('./test/assets/saml20.validResponseSignedMessage.xml').toString();
const validateOpts = {
  thumbprint: 'e606eced42fa3abd0c5693456384f5931b174707',
  audience: 'http://sp.example.com/demo1/metadata.php',
  inResponseTo: 'ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685',
};

describe('response.ts', function () {
  it('RAW response ok', async function () {
    const value = await parse(rawResponse);
    expect(value.audience).to.equal('http://sp.example.com/demo1/metadata.php');
    expect('_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7').to.equal(
      value.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier']
    );
    expect(value.issuer).to.equal('http://idp.example.com/metadata.php');
  });

  it('RAW response not ok', async function () {
    try {
      await parse('rawResponse');
    } catch (error) {
      expect(error).to.be.ok;
    }
  });

  it('ValidateAsync ok', async function () {
    const value = await validate(rawResponse, validateOpts);

    expect(value.audience).to.equal('http://sp.example.com/demo1/metadata.php');
    expect('_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7').to.equal(
      value.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier']
    );
    expect(value.issuer).to.equal('http://idp.example.com/metadata.php');
  });

  it('ValidateAsync RAW response not ok', async function () {
    try {
      await validate('rawResponse', validateOpts);
    } catch (error) {
      expect(error).to.be.ok;
    }
  });
  it('ValidateAsync validateOpts not ok', async function () {
    try {
      await validate(rawResponse, 'validateOpts');
    } catch (error) {
      expect(error).to.be.ok;
    }
  });

  it('ValidateAsync not ok', async function () {
    try {
      await validate('rawResponse', 'validateOpts');
    } catch (error) {
      expect(error).to.be.ok;
    }
  });
});
