import { parseAsync, validateAsync } from '../../lib/response';
import { expect } from 'chai';
import fs from 'fs';

const rawResponse = fs.readFileSync('./test/assets/saml20.rawResponse.xml').toString();
const validateOpts = {
  thumbprint: 'ecd00c7bafd40eed03e98646c9d5a802f39d4b07',
  audience: 'https://saml.boxyhq.com',
  inResponseTo: '_ec9ff74838da0a662a95',
};

describe('response.ts', function () {
  it('RAW response ok', function () {
    expect(parseAsync(rawResponse)).to.be.ok;
  });

  it('RAW response not ok', function () {
    try {
      parseAsync('rawResponse');
    } catch (error) {
      console.log(error);
    }
  });

  it('ValidateAsync ok', function () {
    expect(validateAsync(rawResponse, validateOpts)).to.be.ok;
  });

  it('ValidateAsync RAW response not ok', function () {
    try {
      validateAsync('rawResponse', validateOpts);
    } catch (error) {
      console.log(error);
    }
  });
  it('ValidateAsync validateOpts not ok', function () {
    try {
      validateAsync(rawResponse, 'validateOpts');
    } catch (error) {
      console.log(error);
    }
  });

  it('ValidateAsync not ok', function () {
    try {
      validateAsync('rawResponse', 'validateOpts');
    } catch (error) {
      console.log(error);
    }
  });
});
