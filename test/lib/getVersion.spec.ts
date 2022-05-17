import * as version from '../../lib/getVersion';
import { expect } from 'chai';

describe('getVersion.ts', function () {
  it('getVersion not ok', function () {
    expect(version.getVersion(undefined)).to.be.not.ok;
  });
});
