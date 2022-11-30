import { decryptXml } from '../../lib/decrypt';
import { expect } from 'chai';
import fs from 'fs';

/**
 * Generate keys Without or empty  passphrase
 *
 * openssl req -newkey rsa:2048 -new -nodes -keyout key.pem -out csr.pem
 * openssl x509 -req -days 365 -in csr.pem -signkey key.pem -out server.crt
 * openssl dgst -sha1 csr.der //for generating thumbprint or fingerprint
 *
 *
 *
 */

const samlResponseEncrypted = fs.readFileSync('./test/assets/certificates/oktaEncResponse.xml').toString();
const privateKey = fs.readFileSync('./test/assets/certificates/oktaPrivateKey.pem').toString();

const options = {
  privateKey: privateKey,
};
describe('decrypt.ts', function () {
  it('valid xml', function (done) {
    try {
      const value = decryptXml(samlResponseEncrypted, options);
      expect(value).to.be.not.null;
      done();
    } catch (error) {
      done(error);
    }
  });

  it('empty xml ', function () {
    try {
      decryptXml('', options);
    } catch (error) {
      expect((error as Error).message).to.equal('Undefined Assertion.');
    }
  });
  it('empty privateKey ', function () {
    try {
      decryptXml(samlResponseEncrypted, {
        encPrivateKey: '',
      });
    } catch (error) {
      expect((error as Error).message).to.equal('Exception of Assertion Decryption.');
    }
  });
});
