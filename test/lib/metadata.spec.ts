import { parseMetadataAsync } from '../../lib/metadata';
import { expect } from 'chai';
import fs from 'fs';

const samlMetadata = fs.readFileSync('./test/assets/mock-saml-metadata.xml').toString();

describe('metadata.ts', function () {
  it('saml MetaData ok', function () {
    expect(parseMetadataAsync(samlMetadata)).to.be.ok;
  });

  it('saml MetaData not ok', function () {
    try {
      parseMetadataAsync('samlMetadata');
    } catch (error) {
      console.log(error);
    }
  });
});
