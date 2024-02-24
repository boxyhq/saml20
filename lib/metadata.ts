import { getAttribute } from './utils';
import { thumbprint } from './utils';
import crypto from 'crypto';

import xml2js from 'xml2js';

const BEGIN = '-----BEGIN CERTIFICATE-----';
const END = '-----END CERTIFICATE-----';

const parseMetadata = async (idpMeta: string, validateOpts): Promise<Record<string, any>> => {
  return new Promise((resolve, reject) => {
    // Some Providers do not escape the & character in the metadata, for now these have been encountered in errorURL
    idpMeta = idpMeta.replace(/errorURL=".*?"/g, '');
    xml2js.parseString(
      idpMeta,
      {
        tagNameProcessors: [xml2js.processors.stripPrefix],
        strict: true,
      },
      (err, res) => {
        if (err) {
          reject(err);
          return;
        }

        const entityID = getAttribute(res, 'EntityDescriptor.$.entityID');
        let X509Certificates: string[] = [];
        const X509CertificatesWithoutSigningAttr: string[] = [];
        let ssoPostUrl: null | undefined = null;
        let ssoRedirectUrl: null | undefined = null;
        let loginType = 'idp';
        let sloRedirectUrl: null | undefined = null;
        let sloPostUrl: null | undefined = null;

        let ssoDes: any = getAttribute(res, 'EntityDescriptor.IDPSSODescriptor', null);
        if (!ssoDes) {
          ssoDes = getAttribute(res, 'EntityDescriptor.SPSSODescriptor', []);
          if (ssoDes.length > 0) {
            loginType = 'sp';
          }
        }

        for (const ssoDesRec of ssoDes) {
          const keyDes = ssoDesRec['KeyDescriptor'];
          for (const keyDesRec of keyDes) {
            const ki = keyDesRec['KeyInfo']?.[0];
            const cd = ki?.['X509Data']?.[0];
            const x509cert = cd?.['X509Certificate']?.[0];
            if (keyDesRec['$'] && keyDesRec['$'].use === 'signing') {
              x509cert && X509Certificates.push(x509cert);
            } else {
              x509cert && X509CertificatesWithoutSigningAttr.push(x509cert);
            }
          }

          const ssoSvc = ssoDesRec['SingleSignOnService'] || ssoDesRec['AssertionConsumerService'] || [];
          for (const ssoSvcRec of ssoSvc) {
            if (getAttribute(ssoSvcRec, '$.Binding', '').endsWith('HTTP-POST')) {
              ssoPostUrl = getAttribute(ssoSvcRec, '$.Location');
            } else if (getAttribute(ssoSvcRec, '$.Binding', '').endsWith('HTTP-Redirect')) {
              ssoRedirectUrl = getAttribute(ssoSvcRec, '$.Location');
            }
          }

          const sloSvc = ssoDesRec['SingleLogoutService'] || [];
          for (const sloSvcRec of sloSvc) {
            if (getAttribute(sloSvcRec, '$.Binding', '').endsWith('HTTP-Redirect')) {
              sloRedirectUrl = getAttribute(sloSvcRec, '$.Location');
            } else if (getAttribute(sloSvcRec, '$.Binding', '').endsWith('HTTP-POST')) {
              sloPostUrl = getAttribute(sloSvcRec, '$.Location');
            }
          }

          if (validateOpts?.validateNameIDFormat) {
            let validNameIDFormat = false;
            const nameIDFormats = ssoDesRec['NameIDFormat'] || [];
            for (const nameIDFormat of nameIDFormats) {
              if (validateOpts?.validateNameIDFormat === nameIDFormat) {
                validNameIDFormat = true;
              }
            }

            if (!validNameIDFormat) {
              reject(
                new Error(
                  `Invalid nameIDFormat. Please set 'Name ID Format' to ${validateOpts?.nameIDFormat}`
                )
              );
              return;
            }
          }
        }

        if (X509Certificates.length === 0) {
          if (X509CertificatesWithoutSigningAttr.length !== 0) {
            X509Certificates = X509CertificatesWithoutSigningAttr;
          } else {
            reject(new Error(`Could not find X509Certificate in the IdP metadata.`));
          }
        }

        const ret: Record<string, any> = {
          sso: {},
          slo: {},
        };

        if (entityID) {
          ret.entityID = entityID;
        }

        const tPrints: string[] = [];
        const validTos: string[] = [];
        for (const X509Certificate of X509Certificates) {
          tPrints.push(thumbprint(X509Certificate));
          /**
           * new crypto.X509Certificate fails with the X509Certificate cert without
           * -----BEGIN CERTIFICATE-----
           * and
           * -----END CERTIFICATE-----
           */
          let vt = '';
          if (X509Certificate.indexOf(BEGIN) != -1 && X509Certificate.indexOf(END) != -1) {
            const { validTo } = new crypto.X509Certificate(X509Certificate.trim());
            vt = validTo;
          } else if (X509Certificate.indexOf(BEGIN) == -1 && X509Certificate.indexOf(END) != -1) {
            /**
             * Prefixing -----BEGIN CERTIFICATE-----
             */
            const { validTo } = new crypto.X509Certificate(`${BEGIN}\n${X509Certificate.trim()}`);
            vt = validTo;
          } else if (X509Certificate.indexOf(BEGIN) != -1 && X509Certificate.indexOf(END) == -1) {
            /**
             * Suffixing -----END CERTIFICATE-----
             */
            const { validTo } = new crypto.X509Certificate(`${X509Certificate.trim()}\n${END}`);
            vt = validTo;
          } else {
            /**
             * Prefixing -----BEGIN CERTIFICATE----- and suffixing -----END CERTIFICATE-----
             */
            const { validTo } = new crypto.X509Certificate(`${BEGIN}\n${X509Certificate.trim()}\n${END}`);
            vt = validTo;
          }

          validTos.push(vt);
        }

        if (X509Certificates.length > 0) {
          ret.publicKey = X509Certificates.map((_) => _.trim()).join(',');
        }

        if (tPrints.length > 0) {
          ret.thumbprint = tPrints.join(',');
        }
        if (validTos.length > 0) {
          ret.validTo = validTos.join(',');
        }

        if (ssoPostUrl) {
          ret.sso.postUrl = ssoPostUrl;
        }

        if (ssoRedirectUrl) {
          ret.sso.redirectUrl = ssoRedirectUrl;
        }

        if (sloRedirectUrl) {
          ret.slo.redirectUrl = sloRedirectUrl;
        }

        if (sloPostUrl) {
          ret.slo.postUrl = sloPostUrl;
        }

        ret.loginType = loginType;

        resolve(ret);
      }
    );
  });
};

export { parseMetadata };
