import saml from '../../lib/index';
import { expect } from 'chai';
import fs from 'fs';

// Tests Configuration
const validResponse = fs.readFileSync('./test/assets/saml20.validResponse.xml').toString();
const errorResponse = fs.readFileSync('./test/assets/saml20.errorResponse.xml').toString();

const issuerName = 'http://idp.example.com/metadata.php';
const thumbprint = 'e606eced42fa3abd0c5693456384f5931b174707';
const certificate =
  'MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==';
const audience = 'http://sp.example.com/demo1/metadata.php';
const inResponseTo = 'ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685';

describe('lib.saml20.response', function () {
  it('Should validate saml 2.0 token using thumbprint', function (done) {
    saml.validateInternal(
      validResponse,
      {
        publicKey: certificate,
        thumbprint: thumbprint,
        bypassExpiration: true,
        inResponseTo: inResponseTo,
      },
      function (err, profile) {
        expect(profile.claims).to.be.ok;
        expect(err).to.not.be.ok;

        expect(issuerName).to.equal(profile.issuer);
        expect('_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7').to.equal(
          profile.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier']
        );
        done();
      }
    );
  });

  it('Should validate saml 2.0 token using certificate', function (done) {
    saml.validateInternal(
      validResponse,
      {
        publicKey: certificate,
        bypassExpiration: true,
        inResponseTo: inResponseTo,
      },
      function (err, profile) {
        expect(profile.claims).to.be.ok;
        expect(err).to.not.be.ok;

        expect(issuerName).to.equal(profile.issuer);
        expect('_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7').to.equal(
          profile.claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier']
        );
        done();
      }
    );
  });

  it('Should validate saml 2.0 token and check audience', function (done) {
    saml.validateInternal(
      validResponse,
      {
        publicKey: certificate,
        audience: audience,
        bypassExpiration: true,
        inResponseTo: inResponseTo,
      },
      function (err, profile) {
        expect(profile.claims).to.be.ok;
        expect(err).to.not.be.ok;
        expect(issuerName).to.equal(profile.issuer);
        done();
      }
    );
  });

  it('Should fail with invalid audience', function (done) {
    saml.validateInternal(
      validResponse,
      {
        publicKey: certificate,
        audience: 'http://any-other-audience.com/',
        bypassExpiration: true,
        inResponseTo: inResponseTo,
      },
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

  it('Should fail with invalid assertion', function (done) {
    saml.validateInternal(
      'invalid-assertion',
      {
        publicKey: certificate,
        bypassExpiration: true,
        inResponseTo: inResponseTo,
      },
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

  it('Should fail with invalid inResponseTo', function (done) {
    saml.validateInternal(
      validResponse,
      {
        publicKey: certificate,
        audience: audience,
        bypassExpiration: true,
        inResponseTo: 'not-the-right-response-to',
      },
      function (err, profile) {
        expect(profile).to.not.be.ok;
        expect(err).to.be.ok;
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

  it('Should not parse saml 2.0 token which has no assertion', function (done) {
    saml.parseInternal(errorResponse, function (err, profile) {
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
    });
  });
});
