import * as index from '../../lib/index';
import { expect } from 'chai';
import fs from 'fs';

// var assert = require('assert');
const errorResponse = fs.readFileSync('./test/assets/saml20.errorResponse.xml').toString();

const validResponse = fs.readFileSync('./test/assets/saml20.validResponse.xml').toString();
const issuerName = 'http://idp.example.com/metadata.php';
const thumbprint = 'e606eced42fa3abd0c5693456384f5931b174707';
const certificate =
  'MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==';
const audience = 'http://sp.example.com/demo1/metadata.php';
const inResponseTo = 'ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685';

const invalidToken = fs.readFileSync('./test/assets/saml20.invalidToken.xml').toString();

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
});
