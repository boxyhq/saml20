import * as version from '../../lib/getVersion';
import { expect } from 'chai';
import fs from 'fs';

const assertion = fs.readFileSync('./test/assets/saml20.rawResponse.xml').toString();

describe('getVersion.ts', function () {
  it('getVersion  ok', function () {
    expect(version.getVersion(undefined)).to.be.not.ok;
  });
});
