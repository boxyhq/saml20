import { assertion } from '../../lib/decrypt';
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
  it('valid xml', function () {
    try {
      const value = assertion(options, samlResponseEncrypted);
      expect(value).to.be.ok;
    } catch (error) {
      console.log(error);
    }
  });

  it('empty xml ', function () {
    try {
      const _value = assertion(options, '');
    } catch (error) {
      expect(error).to.equal('Error Undefined Assertion.');
    }
  });
  it('empty privateKey ', function () {
    try {
      const _value = assertion(
        {
          encPrivateKey: '',
        },
        samlResponseEncrypted
      );
    } catch (error) {
      expect(error).to.equal('Error Exception of Assertion Decryption.');
    }
  });
});
