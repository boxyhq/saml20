import * as rambda from 'rambda';
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

        const entityID = rambda.path('EntityDescriptor.$.entityID', res);
        const X509Certificates: string[] = [];
        let ssoPostUrl: null | undefined = null;
        let ssoRedirectUrl: null | undefined = null;
        let loginType = 'idp';
        let sloRedirectUrl: null | undefined = null;
        let sloPostUrl: null | undefined = null;

        let ssoDes: any = rambda.pathOr(null, 'EntityDescriptor.IDPSSODescriptor', res);
        if (!ssoDes) {
          ssoDes = rambda.pathOr([], 'EntityDescriptor.SPSSODescriptor', res);
          if (ssoDes.length > 0) {
            loginType = 'sp';
          }
        }

        let firstX509Certificate;
        for (const ssoDesRec of ssoDes) {
          const keyDes = ssoDesRec['KeyDescriptor'];
          for (const keyDesRec of keyDes) {
            if (firstX509Certificate === undefined) {
              const ki = keyDesRec['KeyInfo']?.[0];
              const cd = ki?.['X509Data']?.[0];
              cd?.['X509Certificate']?.[0] && (firstX509Certificate = cd['X509Certificate'][0]);
            }
            if (keyDesRec['$'] && keyDesRec['$'].use === 'signing') {
              const ki = keyDesRec['KeyInfo']?.[0];
              const cd = ki?.['X509Data']?.[0];
              cd?.['X509Certificate']?.[0] && X509Certificates.push(cd['X509Certificate'][0]);
            }
          }

          const ssoSvc = ssoDesRec['SingleSignOnService'] || ssoDesRec['AssertionConsumerService'] || [];
          for (const ssoSvcRec of ssoSvc) {
            if (rambda.pathOr('', '$.Binding', ssoSvcRec).endsWith('HTTP-POST')) {
              ssoPostUrl = rambda.path('$.Location', ssoSvcRec);
            } else if (rambda.pathOr('', '$.Binding', ssoSvcRec).endsWith('HTTP-Redirect')) {
              ssoRedirectUrl = rambda.path('$.Location', ssoSvcRec);
            }
          }

          const sloSvc = ssoDesRec['SingleLogoutService'] || [];
          for (const sloSvcRec of sloSvc) {
            if (rambda.pathOr('', '$.Binding', sloSvcRec).endsWith('HTTP-Redirect')) {
              sloRedirectUrl = rambda.path('$.Location', sloSvcRec);
            } else if (rambda.pathOr('', '$.Binding', sloSvcRec).endsWith('HTTP-POST')) {
              sloPostUrl = rambda.path('$.Location', sloSvcRec);
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
          if (firstX509Certificate !== undefined) {
            X509Certificates[0] = firstX509Certificate;
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
