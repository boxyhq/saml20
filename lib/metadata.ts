import * as rambda from 'rambda';
import thumbprint from 'thumbprint';
import crypto from 'crypto';

import xml2js from 'xml2js';

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
      (err: Error, res) => {
        if (err) {
          reject(err);
          return;
        }

        const entityID = rambda.path('EntityDescriptor.$.entityID', res);
        let X509Certificate = null;
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

        for (const ssoDesRec of ssoDes) {
          const keyDes = ssoDesRec['KeyDescriptor'];
          for (const keyDesRec of keyDes) {
            if (keyDesRec['$'] && keyDesRec['$'].use === 'signing') {
              const ki = keyDesRec['KeyInfo'][0];
              const cd = ki['X509Data'][0];
              X509Certificate = cd['X509Certificate'][0];
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

        const ret: Record<string, any> = {
          sso: {},
          slo: {},
        };

        if (entityID) {
          ret.entityID = entityID;
        }

        if (X509Certificate) {
          ret.thumbprint = thumbprint.calculate(X509Certificate);
          const { validTo } = new crypto.X509Certificate(X509Certificate);
          ret.validTo = validTo;
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
