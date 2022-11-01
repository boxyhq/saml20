import xmlcrypto from 'xml-crypto';
import thumbprint from 'thumbprint';
import { DOMParser } from '@xmldom/xmldom';

const select = xmlcrypto.xpath;
const SignedXml = xmlcrypto.SignedXml;

const certToPEM = (cert) => {
  if (cert.indexOf('BEGIN CERTIFICATE') === -1 && cert.indexOf('END CERTIFICATE') === -1) {
    cert = cert.match(/.{1,64}/g).join('\n');
    cert = '-----BEGIN CERTIFICATE-----\n' + cert;
    cert = cert + '\n-----END CERTIFICATE-----\n';
    return cert;
  } else {
    return cert;
  }
};

const hasValidSignature = (xml, cert, certThumbprint) => {
  const doc = new DOMParser().parseFromString(xml);
  let signature =
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

  if (!signature) {
    signature = select(doc, "//*[local-name(.)='Signature']", [0]);
  }

  const signed = new SignedXml(null, {
    idAttribute: 'AssertionID',
  });

  let calculatedThumbprint;

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

    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
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
  const { valid, calculatedThumbprint, id } = hasValidSignature(xml, cert, certThumbprint);

  if (valid) {
    if (cert) {
      return id;
    }

    if (certThumbprint && calculatedThumbprint.toUpperCase() === certThumbprint.toUpperCase()) {
      return id;
    }
  }
};

export { hasValidSignature, validateSignature, certToPEM };
