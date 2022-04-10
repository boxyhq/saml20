'use strict';

var select = require('xml-crypto').xpath;
var SignedXml = require('xml-crypto').SignedXml;
var Dom = require('@xmldom/xmldom').DOMParser;
var thumbprint = require('thumbprint');

const certToPEM = (cert) => {
  if (
    cert.indexOf('BEGIN CERTIFICATE') === -1 &&
    cert.indexOf('END CERTIFICATE') === -1
  ) {
    cert = cert.match(/.{1,64}/g).join('\n');
    cert = '-----BEGIN CERTIFICATE-----\n' + cert;
    cert = cert + '\n-----END CERTIFICATE-----\n';
    return cert;
  } else {
    return cert;
  }
};

const hasValidSignature = (xml, cert, certThumbprint) => {
  const doc = new Dom().parseFromString(xml);
  const signature =
    select(
      doc,
      "/*/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']"
    )[0] ||
    select(
      doc,
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']"
    )[0] ||
    select(
      doc,
      "/*/*/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']"
    )[0];
  const signed = new SignedXml(null, {
    idAttribute: 'AssertionID',
  });

  var calculatedThumbprint;

  signed.keyInfoProvider = {
    getKey: function getKey(keyInfo) {
      if (certThumbprint) {
        const embeddedSignature = keyInfo[0].getElementsByTagNameNS(
          'http://www.w3.org/2000/09/xmldsig#',
          'X509Certificate'
        );

        if (embeddedSignature.length > 0) {
          const base64cer = embeddedSignature[0].firstChild.toString();

          calculatedThumbprint = thumbprint.calculate(base64cer);

          return certToPEM(base64cer);
        }
      }

      return certToPEM(cert);
    },
    getKeyInfo: function getKeyInfo(key) {
      return '<X509Data></X509Data>';
    },
  };

  signed.loadSignature(signature.toString());

  const valid = signed.checkSignature(xml);

  let id;
  if (valid) {
    const uri = signed.references[0].uri;
    id = uri[0] === '#' ? uri.substring(1) : uri;
  }

  return {
    valid,
    calculatedThumbprint,
    id,
  };
};

const validateSignature = (xml, cert, certThumbprint) => {
  const { valid, calculatedThumbprint, id } = hasValidSignature(
    xml,
    cert,
    certThumbprint
  );

  if (valid) {
    if (cert) {
      return id;
    }

    if (
      certThumbprint &&
      calculatedThumbprint.toUpperCase() === certThumbprint.toUpperCase()
    ) {
      return id;
    }
  }
};

module.exports = {
  hasValidSignature,
  validateSignature,
  certToPEM,
};
