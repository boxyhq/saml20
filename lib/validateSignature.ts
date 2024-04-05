import { SignedXml } from 'xml-crypto';
import { select } from 'xpath';
import { thumbprint } from './utils';
import { parseFromString } from './utils';

const isMultiCert = (cert) => {
  return cert.indexOf(',') !== -1;
};

const _certToPEM = (cert) => {
  if (cert.indexOf('BEGIN CERTIFICATE') === -1 && cert.indexOf('END CERTIFICATE') === -1) {
    cert = cert.match(/.{1,64}/g).join('\n');
    cert = '-----BEGIN CERTIFICATE-----\n' + cert;
    cert = cert + '\n-----END CERTIFICATE-----\n';
    return cert;
  } else {
    return cert;
  }
};

const certToPEM = (cert) => {
  if (isMultiCert(cert)) {
    const _certs = cert.split(',');
    return _certs.map((_cert) => _certToPEM(_cert)).join('');
  }

  return _certToPEM(cert);
};

const hasValidSignature = (xml, cert, certThumbprint) => {
  let res = _hasValidSignature(xml, cert, certThumbprint);

  // sanitize and validate if validation failed first time
  if (!res.valid) {
    xml = xml.replace(/&#x(d|D);/gi, '');
    res = _hasValidSignature(xml, cert, certThumbprint);
  }

  return res;
};

const _hasValidSignature = (xml, cert, certThumbprint) => {
  const doc = parseFromString(xml);
  let signature =
    select(
      "/*/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc
    )?.[0] ||
    select(
      "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc
    )?.[0] ||
    select(
      "/*/*/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc
    )?.[0];

  if (!signature) {
    signature = select("//*[local-name(.)='Signature']", doc)?.[0];
  }

  const signed = new SignedXml({
    idAttribute: 'AssertionID',
  });

  signed.loadSignature(signature.toString());

  let valid;
  let id, calculatedThumbprint;
  // Check if cert contains multiple
  // Load each cert and run checkSignature
  if (cert && isMultiCert(cert)) {
    const _certs = cert.split(',');
    for (const _cert of _certs) {
      signed.getCertFromKeyInfo = () => {
        return _certToPEM(_cert);
      };
      try {
        valid = signed.checkSignature(xml);
      } catch (err) {
        //noop
      }
      if (valid) {
        break;
      }
    }
  } else {
    signed.getCertFromKeyInfo = function getKey(keyInfo) {
      if (certThumbprint) {
        const embeddedCert = keyInfo!.childNodes[0].ownerDocument!.getElementsByTagNameNS(
          'http://www.w3.org/2000/09/xmldsig#',
          'X509Certificate'
        );

        if (embeddedCert.length > 0) {
          const base64cer = embeddedCert[0].firstChild!.toString();

          calculatedThumbprint = thumbprint(base64cer);

          return certToPEM(base64cer);
        }
      }

      return certToPEM(cert);
    };

    valid = signed.checkSignature(xml);
  }

  if (valid) {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
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
  if (cert && certThumbprint) {
    throw new Error('You should provide either cert or certThumbprint, not both');
  }

  const { valid, calculatedThumbprint, id } = hasValidSignature(xml, cert, certThumbprint);

  if (valid) {
    if (certThumbprint) {
      const thumbprints = certThumbprint.split(',');

      if (thumbprints.includes(calculatedThumbprint)) {
        return id;
      }
    }

    if (cert) {
      return id;
    }
  }
};

export { hasValidSignature, validateSignature, certToPEM };
