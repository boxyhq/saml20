import saml from './index';

import { SAMLProfile } from './typings';

const parse = async (rawAssertion: string): Promise<SAMLProfile> => {
  return new Promise((resolve, reject) => {
    saml.parseInternal(rawAssertion, function onParseAsync(err: Error, profile: SAMLProfile) {
      if (err) {
        reject(err);
        return;
      }

      resolve(profile);
    });
  });
};

const validate = async (rawAssertion: string, options): Promise<SAMLProfile> => {
  return new Promise((resolve, reject) => {
    saml.validateInternal(rawAssertion, options, function onValidateAsync(err, profile: SAMLProfile) {
      if (err) {
        reject(err);
        return;
      }

      resolve(profile);
    });
  });
};

export { parse, validate };
