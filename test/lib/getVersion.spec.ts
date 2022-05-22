import * as version from '../../lib/getVersion';
import { expect } from 'chai';
import fs from 'fs';

const assertion = fs.readFileSync('./test/assets/saml20.validResponseSignedMessage.xml').toString();

describe('getVersion.ts', function () {
  it('getVersion not ok', function () {
    expect(version.getVersion(undefined)).to.be.not.ok;
  });
});
