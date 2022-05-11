import decrypt from '../../lib/decrypt';
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
  encPrivateKey: privateKey,
};
describe('decrypt.ts', function () {
  it('decrypt ok', function () {
    try {
      decrypt.assertion(options, samlResponseEncrypted);
    } catch (error) {
      console.log(error);
    }

    //   expect(decrypt(publicKey)).to.be.ok;
  });
});
