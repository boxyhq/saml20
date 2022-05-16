import saml from '../../lib/index';
import { assertion } from '../../lib/decrypt';
import { expect } from 'chai';
import fs from 'fs';

let validResponse;

const oneLoginSamlResponseEncrypted = fs
  .readFileSync('./test/assets/certificates/oneloginEncResponse.xml')
  .toString();
const oneLoginPrivateKey = fs.readFileSync('./test/assets/certificates/oneloginPrivateKey.pem').toString();
const oneLoginThumbprint = '56d68c4616d0909ac25dade25c36a7bd792eaf62';
const oneLoginInResponseTo = '_25b63bdecac84d524aec';
const oneLoginCertificate = fs.readFileSync('./test/assets/certificates/oneloginPublicKey.crt').toString();
const oneLoginIssuerName = 'https://app.onelogin.com/saml/metadata/2f5926c1-a571-4702-9ed5-12309c86f9c7';
const oneLoginProfileClaims = 'hojit22291@abincol.com';

const oktaSamlResponseEncrypted = fs
  .readFileSync('./test/assets/certificates/oktaEncResponse.xml')
  .toString();
const oktaPrivateKey = fs.readFileSync('./test/assets/certificates/oktaPrivateKey.pem').toString();
const oktaThumbprint = '008c1aa2ed3cdb5c064c99b3d1619346b619008a';
const oktaInResponseTo = '_f81f46f19ccf489ab1a1';
const oktaCertificate = fs.readFileSync('./test/assets/certificates/oktaPublicKey.crt').toString();
const oktaIssuerName = 'http://www.okta.com/exkymhf9ve6PI9KfY696';
const oktaProfileClaims = 'hojit22291@abincol.com';

const oneLoginOptions = {
  encPrivateKey: oneLoginPrivateKey,
};
const oktaOptions = {
  encPrivateKey: oktaPrivateKey,
};
describe('decrypt.response.spec', function () {
  it('One Login Should validate saml 2.0 token using thumbprint', function (done) {
    validResponse = assertion(oneLoginOptions, oneLoginSamlResponseEncrypted);
    saml.validateInternal(
      validResponse.toString(),
      {
        publicKey: oneLoginCertificate,
        thumbprint: oneLoginThumbprint,
        bypassExpiration: true,
        inResponseTo: oneLoginInResponseTo,
      },
      function (err, profile) {
        expect(profile.claims).to.be.ok;
        expect(err).to.not.be.ok;
        expect(oneLoginIssuerName).to.equal(profile.issuer);
        expect(oneLoginProfileClaims).to.equal(
          profile.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier']
        );
        done();
      }
    );
  });
  it('One Login Should validate saml 2.0 token using thumbprint Only', function (done) {
    validResponse = assertion(oneLoginOptions, oneLoginSamlResponseEncrypted);
    saml.validateInternal(
      validResponse.toString(),
      {
        // publicKey: certificate,
        thumbprint: oneLoginThumbprint,
        bypassExpiration: true,
        inResponseTo: oneLoginInResponseTo,
      },
      function (err, profile) {
        expect(profile.claims).to.be.ok;

        expect(err).to.not.be.ok;

        expect(oneLoginIssuerName).to.equal(profile.issuer);
        expect(oneLoginProfileClaims).to.equal(
          profile.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier']
        );
        done();
      }
    );
  });

  it('Okta Should validate saml 2.0 token using thumbprint', function (done) {
    validResponse = assertion(oktaOptions, oktaSamlResponseEncrypted);
    saml.validateInternal(
      validResponse.toString(),
      {
        publicKey: oktaCertificate,
        thumbprint: oktaThumbprint,
        bypassExpiration: true,
        inResponseTo: oktaInResponseTo,
      },
      function (err, profile) {
        expect(profile.claims).to.be.ok;
        expect(err).to.not.be.ok;
        expect(oktaIssuerName).to.equal(profile.issuer);
        expect(oktaProfileClaims).to.equal(
          profile.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier']
        );
        done();
      }
    );
  });
  it('Okta Should validate saml 2.0 token using thumbprint Only', function (done) {
    validResponse = assertion(oktaOptions, oktaSamlResponseEncrypted);
    saml.validateInternal(
      validResponse.toString(),
      {
        // publicKey: certificate,
        thumbprint: oktaThumbprint,
        bypassExpiration: true,
        inResponseTo: oktaInResponseTo,
      },
      function (err, profile) {
        expect(profile.claims).to.be.ok;

        expect(err).to.not.be.ok;

        expect(oktaIssuerName).to.equal(profile.issuer);
        expect(oktaProfileClaims).to.equal(
          profile.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier']
        );
        done();
      }
    );
  });
});
