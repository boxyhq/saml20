import { parse, validate } from '../../lib/response';
import { expect } from 'chai';
import fs from 'fs';

const rawResponse = fs.readFileSync('./test/assets/saml20.validResponseSignedMessage.xml').toString();
const validateOpts = {
  thumbprint: 'e606eced42fa3abd0c5693456384f5931b174707',
  audience: 'http://sp.example.com/demo1/metadata.php',
  inResponseTo: 'ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685',
};
const errorResponse = fs.readFileSync('./test/assets/saml20.errorResponse.xml').toString();
const validResponse = fs.readFileSync('./test/assets/saml20.validResponse.xml').toString();
const certificate =
  'MIICDzCCAXygAwIBAgIQVWXAvbbQyI5BcFe0ssmeKTAJBgUrDgMCHQUAMB8xHTAbBgNVBAMTFGlkZW50aXR5LmtpZG96ZW4uY29tMB4XDTEyMDcwNTE4NTEzNFoXDTM5MTIzMTIzNTk1OVowHzEdMBsGA1UEAxMUaWRlbnRpdHkua2lkb3plbi5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJ1GPvzmIZ5OO5by9Qn2fsSuLIJWHfewRzgxcZ6SykzmjD4H1aGOtjUg5EFgQ/HWxa16oJ+afWa0dyeXAiLl5gas71FzgzeODL1STIuyLXFVLQvIJX/HTQU+qcMBlwsscdvVaJSYQsI3OC8Ny5GZvt1Jj2G9TzMTg2hLk5OfO1zxAgMBAAGjVDBSMFAGA1UdAQRJMEeAEDSvlNc0zNIzPd7NykB3GAWhITAfMR0wGwYDVQQDExRpZGVudGl0eS5raWRvemVuLmNvbYIQVWXAvbbQyI5BcFe0ssmeKTAJBgUrDgMCHQUAA4GBAIMmDNzL+Kl5omgxKRTgNWMSZAaMLgAo2GVnZyQ26mc3v+sNHRUJYJzdYOpU6l/P2d9YnijDz7VKfOQzsPu5lHK5s0NiKPaSb07wJBWCNe3iwuUNZg2xg/szhiNSWdq93vKJG1mmeiJSuMlMafJVqxC6K5atypwNNBKbpJEj4w5+';
const inResponseTo = 'ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685';
const issuerName = 'https://identity.kidozen.com/';
const audience = 'http://demoscope.com';
const validToken = fs.readFileSync('./test/assets/saml20.validToken.xml').toString();
const invalidToken = fs.readFileSync('./test/assets/saml20.invalidToken.xml').toString();
const invalidWrappedToken = fs.readFileSync('./test/assets/saml20.invalidWrappedToken.xml').toString();

describe('response.ts', function () {
  it('RAW response ok', async function () {
    const response = await parse(rawResponse);
    expect(response.audience).to.equal('http://sp.example.com/demo1/metadata.php');
    expect('_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7').to.equal(
      response.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier']
    );
    expect(response.issuer).to.equal('http://idp.example.com/metadata.php');
  });

  it('RAW response not ok', async function () {
    try {
      await parse('rawResponse');
    } catch (error) {
      const result = (error as Error).message;
      expect(result).to.be.equal('An error occurred trying to parse XML assertion.');
    }
  });

  it('Should not parse saml 2.0 token which has no assertion', async function () {
    try {
      await parse(errorResponse);
    } catch (error) {
      const result = (error as Error).message;
      expect(result).to.be.equal('Invalid assertion.');
    }
  });

  it('An error occurred trying to parse XML assertion.', async function () {
    try {
      await parse('undefined');
    } catch (error) {
      const result = (error as Error).message;
      expect(result).to.be.equal('An error occurred trying to parse XML assertion.');
    }
  });

  it('An error occurred trying to parse assertion', async function () {
    try {
      const response = await parse(validResponse);
      expect(response.audience).to.equal('http://sp.example.com/demo1/metadata.php');
      expect('_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7').to.equal(
        response.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier']
      );
      expect(response.issuer).to.equal('http://idp.example.com/metadata.php');
    } catch (error) {
      const result = (error as Error).message;
      expect(result).to.be.equal('An error occurred trying to parse assertion.');
    }
  });

  it('ValidateAsync ok', async function () {
    const response = await validate(rawResponse, validateOpts);
    expect(response.audience).to.equal('http://sp.example.com/demo1/metadata.php');
    expect('_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7').to.equal(
      response.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier']
    );
    expect(response.issuer).to.equal('http://idp.example.com/metadata.php');
  });

  it('ValidateAsync RAW response not ok', async function () {
    try {
      await validate('rawResponse', validateOpts);
    } catch (error) {
      const result = (error as Error).message;
      expect(result).to.be.equal('Invalid assertion.');
    }
  });

  it('Should fail which has no assertion', async function () {
    try {
      await validate(validResponse, {
        publicKey: certificate,
        bypassExpiration: true,
        inResponseTo: inResponseTo,
      });
    } catch (error) {
      const result = (error as Error).message;
      expect(result).to.be.equal('Invalid assertion signature.');
    }
  });

  it('Should fail which has no publicKey or thumbprint', async function () {
    try {
      await validate(validResponse, {
        publicKey: undefined,
        bypassExpiration: true,
        inResponseTo: inResponseTo,
      });
    } catch (error) {
      const result = (error as Error).message;
      expect(result).to.be.equal('publicKey or thumbprint are options required.');
    }
  });
  it('Assertion is expired.', async function () {
    try {
      validate('invalid-assertion', {
        publicKey: certificate,
        bypassExpiration: true,
        inResponseTo: inResponseTo,
      });
    } catch (error) {
      const result = (error as Error).message;
      expect(result).to.be.equal('Invalid assertion.');
    }
  });

  it('Should validate saml 2.0 token using certificate', async function () {
    const response = await validate(validToken, { publicKey: certificate, bypassExpiration: true });
    expect(issuerName).to.equal(response.issuer);
    expect('demo@kidozen.com').to.equal(
      response.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']
    );
  });

  it('Should validate saml 2.0 token and check audience', async function () {
    const response = await validate(validToken, {
      publicKey: certificate,
      audience: audience,
      bypassExpiration: true,
    });
    expect(issuerName).to.equal(response.issuer);
  });

  it('Should fail with invalid audience', async function () {
    try {
      await validate(validToken, {
        publicKey: certificate,
        audience: 'http://any-other-audience.com/',
        bypassExpiration: true,
      });
    } catch (error) {
      const result = (error as Error).message;
      expect(result).to.be.equal('Invalid audience.');
    }
  });
  it('Should fail with invalid signature', async function () {
    try {
      await validate(invalidToken, { publicKey: certificate, bypassExpiration: true });
    } catch (error) {
      const result = (error as Error).message;
      expect(result).to.be.equal('Invalid assertion signature.');
    }
  });

  it('Should fail with invalid assertion', async function () {
    try {
      await validate('invalid-assertion', { publicKey: certificate, bypassExpiration: true });
    } catch (error) {
      const result = (error as Error).message;
      expect(result).to.be.equal('Invalid assertion.');
    }
  });

  it('Should fail with invalid assertion and possible assertion wrapping', async function () {
    try {
      await validate(invalidWrappedToken, { publicKey: certificate, bypassExpiration: true });
    } catch (error) {
      const result = (error as Error).message;
      expect(result).to.be.equal('Invalid assertion. Possible assertion wrapping.');
    }
  });

  it('Should fail with expired assertion', async function () {
    try {
      await validate(validToken, { publicKey: certificate });
    } catch (error) {
      const result = (error as Error).message;
      expect(result).to.be.equal('Assertion is expired.');
    }
  });

  it('Should parse saml 2.0 without signature validation', async function () {
    const response = await parse(invalidToken);
    expect(issuerName).to.equal(response.issuer);
  });

  it('parseIssuer response ok', async function () {
    const response = await parse(validResponse);
    expect(response.issuer).to.equal('http://idp.example.com/metadata.php');
  });

  it('parseIssuer not ok', async function () {
    try {
      await parse('rawResponse');
    } catch (error) {
      const result = (error as Error).message;
      expect(result).to.be.equal('An error occurred trying to parse XML assertion.');
    }
  });
});
