import * as index from '../../lib/index';
import decryptSAML from '../../lib/decryptSAML';
import { expect } from 'chai';
import fs from 'fs';

let validResponse;

const samlResponseEncrypted = fs
  .readFileSync('./test/assets/certificates/publicEncRespoOneLogin.xml')
  .toString();
const privateKey = fs.readFileSync('./test/assets/certificates/privateKeyOneLogin.pem').toString();
const thumbprint = '56d68c4616d0909ac25dade25c36a7bd792eaf62';
const inResponseTo = '_25b63bdecac84d524aec';
const certificate = fs.readFileSync('./test/assets/certificates/publicKeyOneLogin.crt').toString();
const issuerName = 'https://app.onelogin.com/saml/metadata/2f5926c1-a571-4702-9ed5-12309c86f9c7';
const profileClaims = 'hojit22291@abincol.com';

// const samlResponseEncrypted = fs.readFileSync('./test/assets/certificates/oktaEncResponse.xml').toString();
// const privateKey = fs.readFileSync('./test/assets/certificates/oktaprivatekey.pem').toString();
// const thumbprint = '008c1aa2ed3cdb5c064c99b3d1619346b619008a';
// const inResponseTo = '_f81f46f19ccf489ab1a1';
// const certificate = fs.readFileSync('./test/assets/certificates/oktapublickkey.crt').toString();
// const issuerName = 'http://www.okta.com/exkymhf9ve6PI9KfY696';
// const profileClaims = 'hojit22291@abincol.com';

const options = {
  encPrivateKey: privateKey,
};
describe('decrypt.response.spec', function () {
  it('Should validate saml 2.0 token using thumbprint', function (done) {
    validResponse = decryptSAML.decryptAssertion(options, samlResponseEncrypted);
    index.default.validate(
      validResponse.toString(),
      {
        publicKey: certificate,
        thumbprint: thumbprint,
        bypassExpiration: true,
        inResponseTo: inResponseTo,
      },
      function (err, profile) {
        expect(profile.claims).to.be.ok;
        expect(err).to.not.be.ok;
        expect(issuerName).to.equal(profile.issuer);
        expect(profileClaims).to.equal(
          profile.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier']
        );
        done();
      }
    );
  });
  it('Should validate saml 2.0 token using thumbprint Only', function (done) {
    validResponse = decryptSAML.decryptAssertion(options, samlResponseEncrypted);
    index.default.validate(
      validResponse.toString(),
      {
        // publicKey: certificate,
        thumbprint: thumbprint,
        bypassExpiration: true,
        inResponseTo: inResponseTo,
      },
      function (err, profile) {
        expect(profile.claims).to.be.ok;

        expect(err).to.not.be.ok;

        expect(issuerName).to.equal(profile.issuer);
        expect(profileClaims).to.equal(
          profile.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier']
        );
        done();
      }
    );
  });
});