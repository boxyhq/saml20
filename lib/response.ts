import * as saml from './index';
import crypto from 'crypto';
import * as rambda from 'rambda';
import thumbprint from 'thumbprint';

import xml2js from 'xml2js';

import claims from './claims';
import { SAMLProfile } from './typings';

const parseAsync = async (rawAssertion: string): Promise<SAMLProfile> => {
  return new Promise((resolve, reject) => {
    saml.parse(
      rawAssertion,
      function onParseAsync(err: Error, profile: SAMLProfile) {
        if (err) {
          reject(err);
          return;
        }

        resolve(profile);
      }
    );
  });
};

const validateAsync = async (
  rawAssertion: string,
  options
): Promise<SAMLProfile> => {
  return new Promise((resolve, reject) => {
    saml.validate(
      rawAssertion,
      options,
      function onValidateAsync(err, profile: SAMLProfile) {
        if (err) {
          reject(err);
          return;
        }

        if (profile && profile.claims) {
          // we map claims to our attributes id, email, firstName, lastName where possible. We also map original claims to raw
          profile.claims = claims.map(profile.claims);

          // some providers don't return the id in the assertion, we set it to a sha256 hash of the email
          if (!profile.claims.id) {
            profile.claims.id = crypto
              .createHash('sha256')
              .update(profile.claims.email)
              .digest('hex');
          }
        }

        resolve(profile);
      }
    );
  });
};

const parseMetadataAsync = async (
  idpMeta: string
): Promise<Record<string, any>> => {
  console.log('------inside parseMetadataAsync----');
  return new Promise((resolve, reject) => {
    xml2js.parseString(
      idpMeta,
      { tagNameProcessors: [xml2js.processors.stripPrefix] },
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

        let ssoDes: any = rambda.pathOr(
          null,
          'EntityDescriptor.IDPSSODescriptor',
          res
        );
        if (!ssoDes) {
          ssoDes = rambda.pathOr([], 'EntityDescriptor.SPSSODescriptor', res);
          if (!ssoDes) {
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

          const ssoSvc =
            ssoDesRec['SingleSignOnService'] ||
            ssoDesRec['AssertionConsumerService'] ||
            [];
          for (const ssoSvcRec of ssoSvc) {
            if (
              rambda.pathOr('', '$.Binding', ssoSvcRec).endsWith('HTTP-POST')
            ) {
              ssoPostUrl = rambda.path('$.Location', ssoSvcRec);
            } else if (
              rambda
                .pathOr('', '$.Binding', ssoSvcRec)
                .endsWith('HTTP-Redirect')
            ) {
              ssoRedirectUrl = rambda.path('$.Location', ssoSvcRec);
            }
          }

          const sloSvc = ssoDesRec['SingleLogoutService'] || [];
          for (const sloSvcRec of sloSvc) {
            if (
              rambda
                .pathOr('', '$.Binding', sloSvcRec)
                .endsWith('HTTP-Redirect')
            ) {
              sloRedirectUrl = rambda.path('$.Location', sloSvcRec);
            } else if (
              rambda.pathOr('', '$.Binding', sloSvcRec).endsWith('HTTP-POST')
            ) {
              sloPostUrl = rambda.path('$.Location', sloSvcRec);
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

export { parseAsync, validateAsync, parseMetadataAsync };
