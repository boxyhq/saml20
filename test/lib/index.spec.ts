import * as index from '../../lib/index';
import { expect } from 'chai';
import fs from 'fs';

// var assert = require('assert');
const errorResponse = fs.readFileSync('./test/assets/saml20.errorResponse.xml').toString();

const validResponse = fs.readFileSync('./test/assets/saml20.validResponse.xml').toString();
const issuerName = 'https://identity.kidozen.com/';
const thumbprint = '1aeabdfa4473ecc7efc5947b19436c575574baf8';
const certificate =
  'MIICDzCCAXygAwIBAgIQVWXAvbbQyI5BcFe0ssmeKTAJBgUrDgMCHQUAMB8xHTAbBgNVBAMTFGlkZW50aXR5LmtpZG96ZW4uY29tMB4XDTEyMDcwNTE4NTEzNFoXDTM5MTIzMTIzNTk1OVowHzEdMBsGA1UEAxMUaWRlbnRpdHkua2lkb3plbi5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJ1GPvzmIZ5OO5by9Qn2fsSuLIJWHfewRzgxcZ6SykzmjD4H1aGOtjUg5EFgQ/HWxa16oJ+afWa0dyeXAiLl5gas71FzgzeODL1STIuyLXFVLQvIJX/HTQU+qcMBlwsscdvVaJSYQsI3OC8Ny5GZvt1Jj2G9TzMTg2hLk5OfO1zxAgMBAAGjVDBSMFAGA1UdAQRJMEeAEDSvlNc0zNIzPd7NykB3GAWhITAfMR0wGwYDVQQDExRpZGVudGl0eS5raWRvemVuLmNvbYIQVWXAvbbQyI5BcFe0ssmeKTAJBgUrDgMCHQUAA4GBAIMmDNzL+Kl5omgxKRTgNWMSZAaMLgAo2GVnZyQ26mc3v+sNHRUJYJzdYOpU6l/P2d9YnijDz7VKfOQzsPu5lHK5s0NiKPaSb07wJBWCNe3iwuUNZg2xg/szhiNSWdq93vKJG1mmeiJSuMlMafJVqxC6K5atypwNNBKbpJEj4w5+';
const audience = 'http://demoscope.com';
const inResponseTo = 'ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685';

const invalidToken = fs.readFileSync('./test/assets/saml20.invalidToken.xml').toString();
const validToken = fs.readFileSync('./test/assets/saml20.validToken.xml').toString();

const invalidWrappedToken = fs.readFileSync('./test/assets/saml20.invalidWrappedToken.xml').toString();

describe('index.ts', function () {
  it('Should not parse saml 2.0 token which has no assertion', function (done) {
    index.default.parse(errorResponse, function (err, profile) {
      expect(profile).to.not.be.ok;
      expect(err).to.be.ok;
      done();
      //   assert.strictEqual('Invalid assertion.', err.message);
    });
  });

  it('Should not parse saml 2.0 token which has error rawAssertion is required', function (done) {
    index.default.parse(undefined, function (err) {
      try {
        if (err) {
          expect(err.message).to.equal('rawAssertion is required.');
        }
        done();
      } catch (error) {
        done();
      }
    });
  });
  it('An error occurred trying to parse XML assertion.', function (done) {
    index.default.parse('undefined', function (err) {
      try {
        if (err) {
          expect(err.message).to.equal('An error occurred trying to parse XML assertion.');
        }
        done();
      } catch (error) {
        done();
      }
    });
  });
  it('An error occurred trying to parse assertion', function (done) {
    index.default.parse(validResponse, function (err) {
      try {
        if (err) {
          expect(err.message).to.equal('An error occurred trying to parse assertion.');
        }
        done();
      } catch (error) {
        done();
      }
    });
  });

  it('Invalid assertion', function (done) {
    index.default.parse('undefined', function (err) {
      try {
        if (err) {
          expect(err.message).to.equal('Invalid assertion.');
        }
        done();
      } catch (error) {
        done();
      }
    });
  });
  it('SAML Assertion version not supported', function (done) {
    index.default.parse(validResponse, function (err) {
      try {
        if (err) {
          expect(err.message).to.equal('SAML Assertion version not supported.');
        }
        done();
      } catch (error) {
        done();
      }
    });
  });

  it('Should fail which has no assertion', function (done) {
    index.default.validate(
      undefined,
      {
        publicKey: certificate,
        bypassExpiration: true,
        inResponseTo: inResponseTo,
      },
      function (err) {
        try {
          if (err) {
            expect(err.message).to.equal('Invalid assertion signature.');
          }
          done();
        } catch (error) {
          done();
        }
      }
    );
  });

  it('Should fail which has no publicKey or thumbprint', function (done) {
    index.default.validate(
      validResponse,
      {
        publicKey: undefined,
        bypassExpiration: true,
        inResponseTo: inResponseTo,
      },
      function (err) {
        try {
          if (err) {
            expect(err.message).to.equal('publicKey or thumbprint are options required.');
          }
          done();
        } catch (error) {
          done();
        }
      }
    );
  });

  it('Validate An error occurred trying to parse assertion', function (done) {
    index.default.validate(
      errorResponse,
      {
        publicKey: certificate,
        bypassExpiration: true,
        inResponseTo: inResponseTo,
      },
      function (err) {
        try {
          if (err) {
            expect(err.message).to.equal('An error occurred trying to parse assertion.');
          }
          done();
        } catch (error) {
          done();
        }
      }
    );
  });

  it('Assertion is expired.', function (done) {
    index.default.validate(
      validResponse,
      {
        publicKey: certificate,
        bypassExpiration: true,
        inResponseTo: inResponseTo,
      },
      function (err) {
        try {
          if (err) {
            expect(err.message).to.equal('Assertion is expired.');
          }
          done();
        } catch (error) {
          done();
        }
      }
    );
  });

  it('Should fail with invalid assertion', function (done) {
    index.default.validate(
      'invalid-assertion',
      {
        publicKey: certificate,
        bypassExpiration: true,
        inResponseTo: inResponseTo,
      },
      function (err) {
        try {
          if (err) {
            expect(err.message).to.equal('Invalid assertion.');
          }
          done();
        } catch (error) {
          done();
        }
      }
    );
  });
  it('Should fail with invalid audience', function (done) {
    index.default.validate(
      validResponse,
      {
        publicKey: certificate,
        audience: 'http://any-other-audience.com/',
        bypassExpiration: true,
        inResponseTo: inResponseTo,
      },

      function (err) {
        try {
          if (err) {
            expect(err.message).to.equal('Invalid audience.');
          }
          done();
        } catch (error) {
          done();
        }
      }
    );
  });
  it('Should fail with invalid inResponseTo', function (done) {
    index.default.validate(
      validResponse,
      {
        publicKey: certificate,
        audience: audience,
        bypassExpiration: true,
        inResponseTo: 'not-the-right-response-to',
      },
      function (err) {
        try {
          if (err) {
            expect(err.message).to.equal('Invalid InResponseTo.');
          }
          done();
        } catch (error) {
          done();
        }
      }
    );
  });

  it('Should validate saml 2.0 token using thumbprint', function (done) {
    index.default.validate(
      validToken,
      {
        publicKey: certificate,
        thumbprint: thumbprint,
        bypassExpiration: true,
      },
      function (err, profile) {
        expect(profile.claims).to.be.ok;
        expect(err).to.not.be.ok;

        expect(issuerName).to.equal(profile.issuer);
        expect('demo@kidozen.com').to.equal(
          profile.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']
        );
        done();
      }
    );
  });

  it('Should validate saml 2.0 token using certificate', function (done) {
    index.default.validate(
      validToken,
      { publicKey: certificate, bypassExpiration: true },
      function (err, profile) {
        expect(profile.claims).to.be.ok;
        expect(err).to.not.be.ok;

        expect(issuerName).to.equal(profile.issuer);
        expect('demo@kidozen.com').to.equal(
          profile.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']
        );
        done();
      }
    );
  });

  it('Should validate saml 2.0 token and check audience', function (done) {
    index.default.validate(
      validToken,
      { publicKey: certificate, audience: audience, bypassExpiration: true },
      function (err, profile) {
        expect(profile.claims).to.be.ok;
        expect(err).to.not.be.ok;
        expect(issuerName).to.equal(profile.issuer);
        done();
      }
    );
  });

  it('Should fail with invalid audience', function (done) {
    index.default.validate(
      validToken,
      {
        publicKey: certificate,
        audience: 'http://any-other-audience.com/',
        bypassExpiration: true,
      },
      function (err, profile) {
        expect(profile).to.not.be.ok;
        expect(err).to.be.ok;
        try {
          if (err) {
            expect(err.message).to.equal('nvalid audience.');
          }
          done();
        } catch (error) {
          done();
        }
      }
    );
  });
  it('Should fail with invalid signature', function (done) {
    index.default.validate(
      invalidToken,
      { publicKey: certificate, bypassExpiration: true },
      function (err, profile) {
        expect(profile).to.not.be.ok;
        expect(err).to.be.ok;
        try {
          if (err) {
            expect(err.message).to.equal('Invalid assertion signature.');
          }
          done();
        } catch (error) {
          done();
        }
      }
    );
  });

  it('Should fail with invalid assertion', function (done) {
    index.default.validate(
      'invalid-assertion',
      { publicKey: certificate, bypassExpiration: true },
      function (err, profile) {
        expect(profile).to.not.be.ok;
        expect(err).to.be.ok;
        try {
          if (err) {
            expect(err.message).to.equal('Invalid assertion.');
          }
          done();
        } catch (error) {
          done();
        }
      }
    );
  });

  it('Should fail with invalid assertion and possible assertion wrapping', function (done) {
    index.default.validate(
      invalidWrappedToken,
      { publicKey: certificate, bypassExpiration: true },
      function (err, profile) {
        expect(profile).to.not.be.ok;
        expect(err).to.be.ok;
        try {
          if (err) {
            expect(err.message).to.equal('Invalid assertion. Possible assertion wrapping.');
          }
          done();
        } catch (error) {
          done();
        }
      }
    );
  });

  it('Should fail with expired assertion', function (done) {
    index.default.validate(validToken, { publicKey: certificate }, function (err, profile) {
      expect(profile).to.not.be.ok;
      expect(err).to.be.ok;
      try {
        if (err) {
          expect(err.message).to.equal('Assertion is expired.');
        }
        done();
      } catch (error) {
        done();
      }
    });
  });

  it('Should parse saml 2.0 without signature validation', function (done) {
    index.default.parse(invalidToken, function (err, profile) {
      expect(profile.claims).to.be.ok;
      expect(err).to.not.be.ok;
      expect(issuerName).to.equal(profile.issuer);

      done();
    });
  });
});
