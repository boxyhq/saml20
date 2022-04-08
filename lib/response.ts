import * as saml from './index';

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

        resolve(profile);
      }
    );
  });
};

export { parseAsync, validateAsync };
