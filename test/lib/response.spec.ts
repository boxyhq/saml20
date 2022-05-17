import { parseAsync, validateAsync } from '../../lib/response';
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
    expect(await parseAsync(rawResponse)).to.be.ok;
  });

  it('RAW response not ok', async function () {
    try {
      await parseAsync('rawResponse');
    } catch (error) {
      expect(error).to.be.ok;
    }
  });

  it('ValidateAsync ok', async function () {
    expect(await validateAsync(rawResponse, validateOpts)).to.be.ok;
  });

  it('ValidateAsync RAW response not ok', async function () {
    try {
      await validateAsync('rawResponse', validateOpts);
    } catch (error) {
      expect(error).to.be.ok;
    }
  });
  it('ValidateAsync validateOpts not ok', async function () {
    try {
      await validateAsync(rawResponse, 'validateOpts');
    } catch (error) {
      expect(error).to.be.ok;
    }
  });

  it('ValidateAsync not ok', async function () {
    try {
      await validateAsync('rawResponse', 'validateOpts');
    } catch (error) {
      expect(error).to.be.ok;
    }
  });
});
