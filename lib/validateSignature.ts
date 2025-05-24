import { SignedXml } from 'xml-crypto';
import { select } from 'xpath';
import { parseFromString, thumbprint } from './utils';

const isMultiCert = (cert) => {
  return cert.indexOf(',') !== -1;
};

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

// Breaking Change: hasValidSignature now returns:
// if signature is valid: the raw signed xml string
// if signature is invalid: throws error or returns null
// clients are to use the resultant raw xml string to parse their SAML Assertion
// should be internal
const hasValidSignature = (xml, cert, certThumbprint): string | null => {
  xml = sanitizeXML(xml);
  return _hasValidSignature(xml, cert, certThumbprint);
};

const _hasValidSignature = (xml, cert, certThumbprint): string | null => {
  const doc = parseFromString(xml);
  let signature =
    select(
      "/*/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      // @ts-expect-error missing Node properties are not needed
      doc!
    )?.[0] ||
    select(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      // @ts-expect-error missing Node properties are not needed
      doc!
    )?.[0] ||
    select(
      "/*/*/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      // @ts-expect-error missing Node properties are not needed
      doc!
    )?.[0];

  if (!signature) {
    // @ts-expect-error missing Node properties are not needed
    signature = select("//*[local-name(.)='Signature']", doc!)?.[0];
  }

  const signed = new SignedXml({
    idAttribute: 'AssertionID',
  });

  signed.loadSignature(signature);

  let valid;
  // Check if cert contains multiple
  // Load each cert and run checkSignature

  // Case A: Use cert(s) i.e. do not use fingerprint
  if (cert && isMultiCert(cert)) {
    const _certs = cert.split(',');
    for (const _cert of _certs) {
      signed.getCertFromKeyInfo = () => {
        return certToPEM(_cert);
      };
      try {
        valid = signed.checkSignature(xml);
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
      } catch (err) {
        //noop
      }
      if (valid) {
        break;
      }
    }
    if (!valid) {
      throw new Error('invalid signature: Failed to verify signature against all the certificates provided.');
    }
  } else {
    signed.getCertFromKeyInfo = function getKey(keyInfo) {
      // Case A: Let's use the thumbprint
      if (certThumbprint) {
        const embeddedCert = keyInfo!.childNodes[0].ownerDocument!.getElementsByTagNameNS(
          'http://www.w3.org/2000/09/xmldsig#',
          'X509Certificate'
        );

        if (embeddedCert.length > 0) {
          const base64cer = embeddedCert[0].firstChild!.toString();
          // authenticate base64der with trusted fingerprint
          const calculatedThumbprint = thumbprint(base64cer);
          const thumbprints = certThumbprint.split(',');

          if (thumbprints.includes(calculatedThumbprint)) {
            // now we can use it
            return certToPEM(base64cer);
          }
        }
      } else {
        // use pre-configured trusted certificates
        return certToPEM(cert);
      }
    };

    valid = signed.checkSignature(xml);
  }

  if (valid && signed.getSignedReferences().length > 0) {
    return signed.getSignedReferences()[0];
  }
  return null;
};

// Breaking Change: validateSignature now returns:
// if signature is valid: the raw signed xml string
// if signature is invalid: throws error or returns null
// clients are to use the resultant raw xml string to parse their SAML Assertion

const validateSignature = (xml, cert, certThumbprint) => {
  if (cert && certThumbprint) {
    throw new Error('You should provide either cert or certThumbprint, not both');
  }

  return hasValidSignature(xml, cert, certThumbprint);
};

const sanitizeXML = (xml) => {
  return xml.replace(/&#x(d|D);/gi, '');
};

export { hasValidSignature, validateSignature, certToPEM, sanitizeXML };
