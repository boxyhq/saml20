var assert = require('assert');
var fs = require('fs');
var saml = require('../lib/index.js');

// Tests Configuration
// Evil response that wraps the valid response inside the Signature tag
var wrappedInvalidResponse1 = fs
  .readFileSync(
    './test/assets/attacks/wrapping/saml20.wrapped.invalidResponse1.xml'
  )
  .toString();

// Evil response that wraps the valid response
var wrappedInvalidResponse2 = fs
  .readFileSync(
    './test/assets/attacks/wrapping/saml20.wrapped.invalidResponse2.xml'
  )
  .toString();

// Evil assertion at the same level as the valid assertion
var wrappedInvalidAssertion1 = fs
  .readFileSync(
    './test/assets/attacks/wrapping/saml20.wrapped.invalidAssertion1.xml'
  )
  .toString();

// Evil assertion wraps the valid assertion
var wrappedInvalidAssertion2 = fs
  .readFileSync(
    './test/assets/attacks/wrapping/saml20.wrapped.invalidAssertion2.xml'
  )
  .toString();

// Evil assertion with signature wraps the valid assertion
var wrappedInvalidAssertion3 = fs
  .readFileSync(
    './test/assets/attacks/wrapping/saml20.wrapped.invalidAssertion3.xml'
  )
  .toString();

// Evil assertion inside Extensions tag
var wrappedInvalidExtensions1 = fs
  .readFileSync(
    './test/assets/attacks/wrapping/saml20.wrapped.invalidExtensions1.xml'
  )
  .toString();

// Evil assertion with signature inside Extensions tag
var wrappedInvalidExtensions2 = fs
  .readFileSync(
    './test/assets/attacks/wrapping/saml20.wrapped.invalidExtensions2.xml'
  )
  .toString();

var certificate =
  'MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==';
var audience = 'http://sp.example.com/demo1/metadata.php';

describe('lib.saml20.attacks.wrapping', function () {
  it('wrappedInvalidResponse1: Should fail with invalid assertion possible assertion wrapping', function (done) {
    saml.validate(
      wrappedInvalidResponse1,
      {
        publicKey: certificate,
        audience,
        bypassExpiration: true,
      },
      function (err, profile) {
        assert.ok(!profile);
        assert.ok(err);
        assert.strictEqual(
          err.message,
          'Invalid assertion. Possible assertion wrapping.'
        );
        done();
      }
    );
  });

  it('wrappedInvalidResponse2: Should fail with invalid assertion possible assertion wrapping', function (done) {
    saml.validate(
      wrappedInvalidResponse2,
      {
        publicKey: certificate,
        audience,
        bypassExpiration: true,
      },
      function (err, profile) {
        assert.ok(!profile);
        assert.ok(err);
        assert.strictEqual(
          err.message,
          'Invalid assertion. Possible assertion wrapping.'
        );
        done();
      }
    );
  });

  it('wrappedInvalidAssertion1: Should fail with invalid assertion possible assertion wrapping', function (done) {
    saml.validate(
      wrappedInvalidAssertion1,
      {
        publicKey: certificate,
        audience,
        bypassExpiration: true,
      },
      function (err, profile) {
        assert.ok(!profile);
        assert.ok(err);
        assert.strictEqual(
          err.message,
          'Invalid assertion. Possible assertion wrapping.'
        );
        done();
      }
    );
  });

  it('wrappedInvalidAssertion2:Should fail with invalid assertion possible assertion wrapping', function (done) {
    saml.validate(
      wrappedInvalidAssertion2,
      {
        publicKey: certificate,
        audience,
        bypassExpiration: true,
      },
      function (err, profile) {
        assert.ok(!profile);
        assert.ok(err);
        assert.strictEqual(
          err.message,
          'Invalid assertion. Possible assertion wrapping.'
        );
        done();
      }
    );
  });

  it('wrappedInvalidAssertion3: Should fail with invalid assertion possible assertion wrapping', function (done) {
    saml.validate(
      wrappedInvalidAssertion3,
      {
        publicKey: certificate,
        audience: audience,
        bypassExpiration: true,
      },
      function (err, profile) {
        assert.ok(!profile);
        assert.ok(err);
        assert.strictEqual(
          'Invalid assertion. Possible assertion wrapping.',
          err.message
        );
        done();
      }
    );
  });

  it('wrappedInvalidExtensions1: Should fail with invalid assertion', function (done) {
    saml.validate(
      wrappedInvalidExtensions1,
      {
        publicKey: certificate,
        audience: audience,
        bypassExpiration: true,
      },
      function (err, profile) {
        assert.ok(!profile);
        assert.ok(err);
        assert.strictEqual('Invalid assertion.', err.message);
        done();
      }
    );
  });

  it('wrappedInvalidExtensions2: Should fail with invalid assertion', function (done) {
    saml.validate(
      wrappedInvalidExtensions2,
      {
        publicKey: certificate,
        audience: audience,
        bypassExpiration: true,
      },
      function (err, profile) {
        assert.ok(!profile);
        assert.ok(err);
        assert.strictEqual('Invalid assertion.', err.message);
        done();
      }
    );
  });
});
