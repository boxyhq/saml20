import { parseMetadataAsync } from '../../lib/metadata';
import { expect } from 'chai';
import fs from 'fs';

const samlMetadata = fs.readFileSync('./test/assets/mock-saml-metadata.xml').toString();

describe('metadata.ts', function () {
  it('saml Metadata ok', async function () {
    expect(await parseMetadataAsync(samlMetadata)).to.be.ok;
  });

  it('saml Metadata not ok', async function () {
    try {
      await parseMetadataAsync('samlMetadata');
    } catch (error) {
      expect(error).to.be.ok;
    }
  });
});
