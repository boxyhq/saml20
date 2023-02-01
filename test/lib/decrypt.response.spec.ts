import { validate } from '../../lib/response';
import { decryptXml } from '../../lib/decrypt';
import { expect } from 'chai';
import fs from 'fs';

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
  privateKey: oneLoginPrivateKey,
};
const oktaOptions = {
  privateKey: oktaPrivateKey,
};
describe('decrypt.response.spec', function () {
  it('One Login Should validate saml 2.0 token using thumbprint', async function () {
    const validResponse = decryptXml(oneLoginSamlResponseEncrypted, oneLoginOptions);

    const response = await validate(validResponse.toString(), {
      publicKey: oneLoginCertificate,
      thumbprint: oneLoginThumbprint,
      bypassExpiration: true,
      inResponseTo: oneLoginInResponseTo,
    });

    expect(oneLoginIssuerName).to.equal(response.issuer);
    expect(oneLoginProfileClaims).to.equal(
      response.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier']
    );
  });

  it('One Login Should validate saml 2.0 token using thumbprint Only', async function () {
    const validResponse = decryptXml(oneLoginSamlResponseEncrypted, oneLoginOptions);
    const response = await validate(validResponse.toString(), {
      thumbprint: oneLoginThumbprint,
      bypassExpiration: true,
      inResponseTo: oneLoginInResponseTo,
    });
    expect(oneLoginIssuerName).to.equal(response.issuer);
    expect(oneLoginProfileClaims).to.equal(
      response.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier']
    );
  });

  it('Okta Should validate saml 2.0 token using thumbprint', async function () {
    const validResponse = decryptXml(oktaSamlResponseEncrypted, oktaOptions);
    const response = await validate(validResponse.toString(), {
      publicKey: oktaCertificate,
      thumbprint: oktaThumbprint,
      bypassExpiration: true,
      inResponseTo: oktaInResponseTo,
    });
    expect(oktaIssuerName).to.equal(response.issuer);
    expect(oktaProfileClaims).to.equal(
      response.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier']
    );
  });

  it('Okta Should validate saml 2.0 token using thumbprint Only. Also test multiple thumprint validation.', async function () {
    const validResponse = decryptXml(oktaSamlResponseEncrypted, oktaOptions);
    const response = await validate(validResponse.toString(), {
      thumbprint: `${oktaThumbprint},somedummythumbprint`,
      bypassExpiration: true,
      inResponseTo: oktaInResponseTo,
    });
    expect(oktaIssuerName).to.equal(response.issuer);
    expect(oktaProfileClaims).to.equal(
      response.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier']
    );
  });
});
