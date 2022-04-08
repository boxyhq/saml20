const stripCertHeaderAndFooter = (cert: string): string => {
  cert = cert.replace(/-+BEGIN CERTIFICATE-+\r?\n?/, '');
  cert = cert.replace(/-+END CERTIFICATE-+\r?\n?/, '');
  cert = cert.replace(/\r\n/g, '\n');
  return cert;
};

function PubKeyInfo(this: any, pubKey: string) {
  this.pubKey = stripCertHeaderAndFooter(pubKey);

  this.getKeyInfo = function (_key, prefix) {
    prefix = prefix || '';
    prefix = prefix ? prefix + ':' : prefix;
    return `<${prefix}X509Data><${prefix}X509Certificate>${this.pubKey}</${prefix}X509Certificate</${prefix}X509Data>`;
  };
}

const certToPEM = (cert: string) => {
  if (
    cert.indexOf('BEGIN CERTIFICATE') === -1 &&
    cert.indexOf('END CERTIFICATE') === -1
  ) {
    const matches = cert.match(/.{1,64}/g);

    if (matches) {
      cert = matches.join('\n');
      cert = '-----BEGIN CERTIFICATE-----\n' + cert;
      cert = cert + '\n-----END CERTIFICATE-----\n';
    }
  }

  return cert;
};

export { certToPEM, PubKeyInfo };
