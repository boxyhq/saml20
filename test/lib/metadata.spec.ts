import { parseMetadata } from '../../lib/metadata';
import { expect } from 'chai';
import fs from 'fs';

const samlMetadata = fs.readFileSync('./test/assets/mock-saml-metadata.xml').toString();
const samlMetadata1 = fs.readFileSync('./test/assets/mock-saml-metadata1.xml').toString();
const samlMetadata2 = fs.readFileSync('./test/assets/mock-saml-metadata2.xml').toString();
const samlMetadata3 = fs.readFileSync('./test/assets/mock-saml-metadata3.xml').toString();

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
