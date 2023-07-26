const stripCertHeaderAndFooter = (cert: string): string => {
  cert = cert.replace(/-+BEGIN CERTIFICATE-+\r?\n?/, '');
  cert = cert.replace(/-+END CERTIFICATE-+\r?\n?/, '');
  cert = cert.replace(/\r\n/g, '\n');
  return cert;
};

function PubKeyInfo(pubKey: string) {
  const pubKeyTrimmed = stripCertHeaderAndFooter(pubKey);

  return function ({ prefix }) {
    prefix = prefix || '';
    prefix = prefix ? prefix + ':' : prefix;
    return `<${prefix}X509Data><${prefix}X509Certificate>${pubKeyTrimmed}</${prefix}X509Certificate</${prefix}X509Data>`;
  };
}

export { stripCertHeaderAndFooter, PubKeyInfo };
