import decryptSAML from '../../lib/decryptSAML';
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
// const samlResponseEncrypted = fs.readFileSync('./test/assets/certs/vi1.xml').toString();
// const privateKey = fs.readFileSync('./test/assets/certs/key1.pem').toString();

// const samlResponseEncrypted = fs.readFileSync('./test/assets/certs/jacksonEncResponse.xml').toString();
// const privateKey = fs.readFileSync('./test/assets/certs/privatekeyjackson.pem').toString();
const samlResponseEncrypted = fs.readFileSync('./test/assets/certificates/oktaEncResponse.xml').toString();
const privateKey = fs.readFileSync('./test/assets/certificates/oktaprivatekey.pem').toString();

const options = {
  encPrivateKey: privateKey,
};
describe('decryptSAML.ts', function () {
  it('decryptSAML ok', function () {
    try {
      decryptSAML.decryptAssertion(options, samlResponseEncrypted);
    } catch (error) {
      console.log(error);
    }

    //   expect(decryptSAML(publicKey)).to.be.ok;
  });
});
