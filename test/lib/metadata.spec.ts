import { parseMetadataAsync } from '../../lib/metadata';
import { expect } from 'chai';
import fs from 'fs';

const samlMetadata = fs.readFileSync('./test/assets/mock-saml-metadata.xml').toString();

describe('metadata.ts', function () {
  it('saml MetaData ok', async function () {
    const value = await parseMetadataAsync(samlMetadata);
    expect(value.entityID).to.equal('https://saml.example.com/entityid');
    expect(value.thumbprint).to.equal('8996bcc1afff3ff8e41f8025ff034b516050a434');
    expect(value.loginType).to.equal('idp');
    expect(value.sso.postUrl).to.equal('http://localhost:4000/api/saml/sso');
    expect(value.sso.redirectUrl).to.equal('http://localhost:4000/api/saml/sso');
  });

  it('saml MetaData not ok', async function () {
    try {
      await parseMetadataAsync('samlMetadata');
    } catch (error) {
      expect(error).to.be.ok;
    }
  });
});
