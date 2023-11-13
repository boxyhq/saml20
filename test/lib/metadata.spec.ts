import { parseMetadata } from '../../lib/metadata';
import { expect } from 'chai';
import fs from 'fs';

const samlMetadata = fs.readFileSync('./test/assets/mock-saml-metadata.xml').toString();
const samlMetadata1 = fs.readFileSync('./test/assets/mock-saml-metadata1.xml').toString();
const samlMetadata2 = fs.readFileSync('./test/assets/mock-saml-metadata2.xml').toString();
const samlMetadata3 = fs.readFileSync('./test/assets/mock-saml-metadata3.xml').toString();
const samlMetadata4 = fs.readFileSync('./test/assets/mock-saml-metadata4.xml').toString();

describe('metadata.ts', function () {
  it('saml MetaData ok without BEGIN & END notations', async function () {
    const value = await parseMetadata(samlMetadata, {});
    expect(value.entityID).to.equal('https://saml.example.com/entityid');
    expect(value.thumbprint).to.equal('8996bcc1afff3ff8e41f8025ff034b516050a434');
    expect(value.loginType).to.equal('idp');
    expect(value.sso.postUrl).to.equal('http://localhost:4000/api/saml/sso');
    expect(value.sso.redirectUrl).to.equal('http://localhost:4000/api/saml/sso');
    expect(value.validTo).to.equal('Aug 12 10:27:20 3021 GMT');
  });

  it('saml MetaData ok with cert having BEGIN & END notations', async function () {
    const value = await parseMetadata(samlMetadata1, {});
    expect(value.entityID).to.equal('https://saml.example.com/entityid');
    expect(value.thumbprint).to.equal('f9e424fe5fb3422db37859fe29b7f92f11af60a7');
    expect(value.loginType).to.equal('idp');
    expect(value.sso.postUrl).to.equal('http://localhost:4000/api/saml/sso');
    expect(value.sso.redirectUrl).to.equal('http://localhost:4000/api/saml/sso');
    expect(value.validTo).to.equal('Aug 12 10:27:20 3021 GMT');
  });

  it('saml MetaData ok with cert having just END notations', async function () {
    const value = await parseMetadata(samlMetadata2, {});
    expect(value.entityID).to.equal('https://saml.example.com/entityid');
    expect(value.thumbprint).to.equal('8996bcc1afff3ff8e41f8025ff034b516050a434');
    expect(value.loginType).to.equal('idp');
    expect(value.sso.postUrl).to.equal('http://localhost:4000/api/saml/sso');
    expect(value.sso.redirectUrl).to.equal('http://localhost:4000/api/saml/sso');
    expect(value.validTo).to.equal('Aug 12 10:27:20 3021 GMT');
  });

  it('saml MetaData ok with cert having just BEGIN notations', async function () {
    const value = await parseMetadata(samlMetadata3, {});
    expect(value.entityID).to.equal('https://saml.example.com/entityid');
    expect(value.thumbprint).to.equal('f9e424fe5fb3422db37859fe29b7f92f11af60a7');
    expect(value.loginType).to.equal('idp');
    expect(value.sso.postUrl).to.equal('http://localhost:4000/api/saml/sso');
    expect(value.sso.redirectUrl).to.equal('http://localhost:4000/api/saml/sso');
    expect(value.validTo).to.equal('Aug 12 10:27:20 3021 GMT');
  });

  it('saml MetaData ok with multiple signing certs', async function () {
    const value = await parseMetadata(samlMetadata4, {});
    expect(value.entityID).to.equal('https://saml.example.com/entityid');
    expect(value.thumbprint).to.equal(
      '8996bcc1afff3ff8e41f8025ff034b516050a434,f9e424fe5fb3422db37859fe29b7f92f11af60a7'
    );
    expect(value.publicKey).to.equal(`MIICmDCCAYACCQC6LM978TM/gjANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJJ
\t\t\t\t\t\tbjAgFw0yMjA0MTExMDI3MjBaGA8zMDIxMDgxMjEwMjcyMFowDTELMAkGA1UEBhMC
\t\t\t\t\t\tSW4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDgPMN71V4y5VzLw6Ev
\t\t\t\t\t\taQA+oMLzmIpoV/p4Y3AM00FUYbVhVtngvRPCmsKOvIxkTM9kZ6VjVfPmzQet+dDS
\t\t\t\t\t\t+rOmJDH5Y+42du6dJnA0SM/wNWL7nAqfWN6e7q7/Jxa/dYMOhkgV6/7+0jBxHGnn
\t\t\t\t\t\tx/2CEVeDF5+nPsdDh2HlPy0MCXLjXGvRpHB/IHQsUHJFKuOQzTiz1OMQHLnV+FQX
\t\t\t\t\t\tT2kDsGmbM/wZo6xGeH5qcRqZJGgLvtLj8XNe6yVmb1naog7Fr7gjThMichkNDVg2
\t\t\t\t\t\t0/lkxYqIL8zgS2NYXwQ6UOKplUv189kHSbXgQCco0h1oNR2LRTaHoYsRnzLMH2Pv
\t\t\t\t\t\tjVoTAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAMXKnzYEyLFwePXXWE76lq5S+2O2
\t\t\t\t\t\tJIMtygzB3YxOJwvIFWmwDPxqpr4aOpw6T2pQLa3rM1YjW2roNw7B3HHXWoc9F4Av
\t\t\t\t\t\tGAe8T1u0Cu+Tyo8ZFf9VrPg5kZ7x2G+nojFfs8zeuEKdNrUZz4bkgkC7sTWHFsOA
\t\t\t\t\t\toZjUqLyT2tfLnXfYGiXd0qGg9X1bs1x+anAhViltjZ97Eeq8wPtRqhm1hiQyawKT
\t\t\t\t\t\t5qs4oKw0AaKsW4pBQux4h+ZmfvqD+1chBd5Ve/bq9FsEnWNkGyawzmsMSTB9UwDA
\t\t\t\t\t\t+bqiHmfaTXWlQnualNaY3g5v7EDVB4COz6rXXQY/y5Y90BFoho5MqIjGW0I=,-----BEGIN CERTIFICATE-----
\t\t\t\t\t\tMIICmDCCAYACCQC6LM978TM/gjANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJJ
\t\t\t\t\t\tbjAgFw0yMjA0MTExMDI3MjBaGA8zMDIxMDgxMjEwMjcyMFowDTELMAkGA1UEBhMC
\t\t\t\t\t\tSW4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDgPMN71V4y5VzLw6Ev
\t\t\t\t\t\taQA+oMLzmIpoV/p4Y3AM00FUYbVhVtngvRPCmsKOvIxkTM9kZ6VjVfPmzQet+dDS
\t\t\t\t\t\t+rOmJDH5Y+42du6dJnA0SM/wNWL7nAqfWN6e7q7/Jxa/dYMOhkgV6/7+0jBxHGnn
\t\t\t\t\t\tx/2CEVeDF5+nPsdDh2HlPy0MCXLjXGvRpHB/IHQsUHJFKuOQzTiz1OMQHLnV+FQX
\t\t\t\t\t\tT2kDsGmbM/wZo6xGeH5qcRqZJGgLvtLj8XNe6yVmb1naog7Fr7gjThMichkNDVg2
\t\t\t\t\t\t0/lkxYqIL8zgS2NYXwQ6UOKplUv189kHSbXgQCco0h1oNR2LRTaHoYsRnzLMH2Pv
\t\t\t\t\t\tjVoTAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAMXKnzYEyLFwePXXWE76lq5S+2O2
\t\t\t\t\t\tJIMtygzB3YxOJwvIFWmwDPxqpr4aOpw6T2pQLa3rM1YjW2roNw7B3HHXWoc9F4Av
\t\t\t\t\t\tGAe8T1u0Cu+Tyo8ZFf9VrPg5kZ7x2G+nojFfs8zeuEKdNrUZz4bkgkC7sTWHFsOA
\t\t\t\t\t\toZjUqLyT2tfLnXfYGiXd0qGg9X1bs1x+anAhViltjZ97Eeq8wPtRqhm1hiQyawKT
\t\t\t\t\t\t5qs4oKw0AaKsW4pBQux4h+ZmfvqD+1chBd5Ve/bq9FsEnWNkGyawzmsMSTB9UwDA
\t\t\t\t\t\t+bqiHmfaTXWlQnualNaY3g5v7EDVB4COz6rXXQY/y5Y90BFoho5MqIjGW0I=`);
    expect(value.loginType).to.equal('idp');
    expect(value.sso.postUrl).to.equal('http://localhost:4000/api/saml/sso');
    expect(value.sso.redirectUrl).to.equal('http://localhost:4000/api/saml/sso');
    expect(value.validTo).to.equal('Aug 12 10:27:20 3021 GMT,Aug 12 10:27:20 3021 GMT');
  });

  it('saml Metadata validateNameIDFormat ok', async function () {
    expect(
      await parseMetadata(samlMetadata, {
        validateNameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      })
    ).to.be.ok;
  });

  it('saml MetaData not ok', async function () {
    try {
      await parseMetadata('samlMetadata', {
        validateNameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      });
    } catch (error) {
      expect(error).to.be.ok;
    }
  });
});
