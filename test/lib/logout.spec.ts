import assert from 'assert';
import fs from 'fs';
import { parseLogoutResponse, createLogoutRequest } from '../../lib/logout';

const response = fs.readFileSync('./test/assets/logout-response.xml').toString();
const responseFailed = fs.readFileSync('./test/assets/logout-response-failed.xml').toString();
const responseInvalid = 'invalid_data';

describe('logout.ts', function () {
  it('response ok', async function () {
    const res = await parseLogoutResponse(response);
    assert.strictEqual(res.id, '_716cfa40a953610d9d68');
    assert.strictEqual(res.issuer, 'urn:dev-tyj7qyzz.auth0.com');
    assert.strictEqual(res.status, 'urn:oasis:names:tc:SAML:2.0:status:Success');
    assert.strictEqual(res.destination, 'http://localhost:3000/slo');
    assert.strictEqual(res.inResponseTo, '_a0089b303b86a97080ff');
  });

  it('response ok for failed response', async function () {
    const res = await parseLogoutResponse(responseFailed);
    assert.strictEqual(res.id, '_716cfa40a953610d9d68');
    assert.strictEqual(res.issuer, 'urn:dev-tyj7qyzz.auth0.com');
    assert.strictEqual(res.status, 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed');
    assert.strictEqual(res.destination, 'http://localhost:3000/slo');
    assert.strictEqual(res.inResponseTo, '_a0089b303b86a97080ff');
  });

  it('createLogoutRequest ok', async function () {
    const req = createLogoutRequest({
      nameId: 'test',
      providerName: 'test',
      sloUrl: 'http://localhost:3000/slo',
    });

    assert.strictEqual(!!req.id, true);
    assert.strictEqual(!!req.xml, true);
  });

  it('should throw an expected error for response containing invalid xml', async function () {
    await assert.rejects(
      async () => {
        await parseLogoutResponse(responseInvalid);
      },
      (error: any) => {
        assert.strictEqual(error.message.includes('Non-whitespace before first tag'), true);
        return true;
      }
    );
  });
});
