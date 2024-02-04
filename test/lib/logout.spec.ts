import assert from 'assert';
import fs from 'fs';
import { parseLogoutResponse } from '../../lib/logout';

const response = fs.readFileSync('./test/assets/logout-response.xml').toString();
const responseFailed = fs.readFileSync('./test/assets/logout-response-failed.xml').toString();

describe('logout.ts', function () {
  it('response ok', async function () {
    const res = await parseLogoutResponse(response);
    assert.strictEqual(res.id, '_716cfa40a953610d9d68');
    assert.strictEqual(res.issuer, 'urn:dev-tyj7qyzz.auth0.com');
    assert.strictEqual(res.status, 'urn:oasis:names:tc:SAML:2.0:status:Success');
    assert.strictEqual(res.destination, 'http://localhost:3000/slo');
    assert.strictEqual(res.inResponseTo, '_a0089b303b86a97080ff');
  });

  it('response failed', async function () {
    const res = await parseLogoutResponse(responseFailed);
    assert.strictEqual(res.id, '_716cfa40a953610d9d68');
    assert.strictEqual(res.issuer, 'urn:dev-tyj7qyzz.auth0.com');
    assert.strictEqual(res.status, 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed');
    assert.strictEqual(res.destination, 'http://localhost:3000/slo');
    assert.strictEqual(res.inResponseTo, '_a0089b303b86a97080ff');
  });
});
