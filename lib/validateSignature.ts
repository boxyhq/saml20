import { SignedXml } from 'xml-crypto';
import { select } from 'xpath';
import { thumbprint } from './utils';
import { parseFromString } from './utils';

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
  const doc = parseFromString(xml);
  let signature =
    select(
      "/*/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc
    )[0] ||
    select(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc
    )[0] ||
    select(
      "/*/*/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc
    )[0];

  if (!signature) {
    signature = select("//*[local-name(.)='Signature']", doc)[0];
  }

  const signed = new SignedXml({
    idAttribute: 'AssertionID',
  });

  let calculatedThumbprint;

  signed.getCertFromKeyInfo = function getKey(keyInfo) {
    if (certThumbprint) {
      const embeddedSignature = keyInfo!.childNodes[0].ownerDocument!.getElementsByTagNameNS(
        'http://www.w3.org/2000/09/xmldsig#',
        'X509Certificate'
      );

      if (embeddedSignature.length > 0) {
        const base64cer = embeddedSignature[0].firstChild!.toString();

        calculatedThumbprint = thumbprint(base64cer);

        return certToPEM(base64cer);
      }
    }

    return certToPEM(cert);
  };

  signed.loadSignature(signature.toString());

  const valid = signed.checkSignature(xml);

  let id;
  if (valid) {
    // @ts-ignore
    const uri = signed.references[0].uri;
    id = uri![0] === '#' ? uri!.substring(1) : uri;
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

    if (certThumbprint) {
      const thumbprints = certThumbprint.split(',');

      if (thumbprints.includes(calculatedThumbprint)) {
        return id;
      }
    }
  }
};

export { hasValidSignature, validateSignature, certToPEM };
