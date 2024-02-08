import { SAMLProfile } from './typings';
import xml2js from 'xml2js';
import xmlbuilder from 'xmlbuilder';
import crypto from 'crypto';
import { getVersion } from './getVersion';
import { validateSignature } from './validateSignature';
import { decryptXml } from './decrypt';
import { select } from 'xpath';
import saml20 from './saml20';
import { parseFromString } from './utils';
import { sign } from './sign';

const tokenHandlers = {
  '2.0': saml20,
};

class WrapError extends Error {
  inner?: any;
}

const parser = new xml2js.Parser({
  attrkey: '@',
  charkey: '_',
  tagNameProcessors: [xml2js.processors.stripPrefix],
});

/**@deprecated Use parseIssuer instead */
const parse = async (rawAssertion: string): Promise<SAMLProfile> => {
  return new Promise((resolve, reject) => {
    parseInternal(rawAssertion, function onParse(err: Error, profile: SAMLProfile) {
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
    validateInternal(rawAssertion, options, function onValidate(err, profile: SAMLProfile) {
      if (err) {
        reject(err);
        return;
      }
      resolve(profile);
    });
  });
};

const parseInternal = async (rawAssertion, cb) => {
  if (!rawAssertion) {
    cb(new Error('rawAssertion is required.'));
    return;
  }
  // Save the js object derived from xml and check status code
  const assertionObj = await xmlToJs(rawAssertion, cb);

  checkStatusCode(assertionObj, cb);

  parseResponseAndVersion(assertionObj, function onParse(err, assertion, version) {
    if (err) {
      cb(err);
      return;
    }

    parseAttributes(assertion, tokenHandlers[version], cb);
  });
};

const parseIssuer = (rawAssertion) => {
  if (!rawAssertion) {
    throw new Error('rawAssertion is required.');
  }

  const xml = parseFromString(rawAssertion);

  const issuerValue = select(
    "/*[contains(local-name(), 'Response')]/*[local-name(.)='Issuer']",
    xml
  ) as Node[];
  if (issuerValue && issuerValue.length > 0) {
    return issuerValue[0].textContent?.toString();
  }
};

const validateInternal = async (rawAssertion, options, cb) => {
  const originalAssertion = rawAssertion;
  if (!rawAssertion) {
    cb(new Error('rawAssertion is required.'));
    return;
  }

  if (!options || (!options.publicKey && !options.thumbprint)) {
    cb(new Error('publicKey or thumbprint are options required.'));
    return;
  }

  if (options.publicKey && options.thumbprint) {
    cb(new Error('You should provide either cert or certThumbprint, not both'));
    return;
  }

  let decAssertion = false;
  try {
    const { assertion, decrypted } = decryptXml(rawAssertion, options);
    rawAssertion = assertion;
    decAssertion = decrypted;
  } catch (err) {
    cb(err);
    return;
  }

  // Save the js object derived from xml and check status code
  const assertionObj = await xmlToJs(rawAssertion, cb);

  checkStatusCode(assertionObj, cb);

  let validId = null;

  try {
    validId = validateSignature(rawAssertion, options.publicKey, options.thumbprint);
  } catch (e) {
    const error = new WrapError('Invalid assertion.');
    error.inner = e;
    cb(error);
    return;
  }

  if (decAssertion && !validId) {
    // try the fallback verification where signature has been generated on the encrypted SAML by some IdPs (like OpenAthens)
    try {
      validId = validateSignature(originalAssertion, options.publicKey, options.thumbprint);
    } catch (e) {
      const error = new WrapError('Invalid assertion.');
      error.inner = e;
      cb(error);
    }
  }

  if (!validId) {
    cb(new Error('Invalid assertion signature.'));
    return;
  }

  parseResponseAndVersion(assertionObj, function onParse(err, assertion, version, response) {
    if (err) {
      cb(err);
      return;
    }

    const tokenHandler = tokenHandlers[version];

    if (!options.bypassExpiration && !tokenHandler.validateExpiration(assertion)) {
      cb(new Error('Assertion is expired.'));
      return;
    }

    if (options.audience && !tokenHandler.validateAudience(assertion, options.audience)) {
      cb(new Error('Invalid audience.'));
      return;
    }

    if (options.inResponseTo && assertion.inResponseTo && assertion.inResponseTo !== options.inResponseTo) {
      cb(new Error('Invalid InResponseTo.'));
      return;
    }

    if (
      assertion['@'] &&
      assertion['@'].ID !== validId &&
      assertion['@'].Id !== validId &&
      assertion['@'].id !== validId &&
      assertion['@'].AssertionID !== validId
    ) {
      if (
        !response ||
        !response['@'] ||
        (response['@'].ID !== validId && response['@'].Id !== validId && response['@'].id !== validId)
      ) {
        cb(new Error('Invalid assertion. Possible assertion wrapping.'));
        return;
      }
    }

    parseAttributes(assertion, tokenHandler, cb);
  });
};

const xmlToJs = async (rawAssertion, cb) => {
  try {
    const jsObj = await parser.parseStringPromise(rawAssertion);
    return flattenObject(jsObj);
  } catch (err) {
    const error = new WrapError('An error occurred trying to parse XML assertion.');
    error.inner = err;
    cb(error);
  }
};

const checkStatusCode = (assertionObj, cb) => {
  const statusValue =
    assertionObj.Response &&
    assertionObj.Response.Status &&
    assertionObj.Response.Status.StatusCode &&
    assertionObj.Response.Status.StatusCode['@'] &&
    assertionObj.Response.Status.StatusCode['@'].Value;
  const statusParts = statusValue ? statusValue.split(':') : statusValue;
  const status = statusParts
    ? statusParts.length > 0
      ? statusParts[statusParts.length - 1]
      : undefined
    : undefined;

  if (status && status !== 'Success') {
    cb(new Error(`Invalid Status Code (${status}).`));
  }
};

function parseResponseAndVersion(assertionObj, cb) {
  let assertion =
    assertionObj.Assertion ||
    (assertionObj.Response && assertionObj.Response.Assertion) ||
    (assertionObj.RequestSecurityTokenResponse &&
      assertionObj.RequestSecurityTokenResponse.RequestedSecurityToken &&
      assertionObj.RequestSecurityTokenResponse.RequestedSecurityToken.Assertion);
  // if we have an array of assertions then pick first element
  if (assertion && assertion[0]) {
    assertion = assertion[0];
  }

  if (!assertion) {
    cb(new Error('Invalid assertion.'));
    return;
  }

  const version = getVersion(assertion);
  const response = assertionObj.Response;

  if (!version) {
    cb(new Error('SAML Assertion version not supported.'));
    return;
  }

  const tokenHandler = tokenHandlers[version];
  assertion.inResponseTo = tokenHandler.getInResponseTo(assertionObj);

  cb(null, assertion, version, response);
}

function flattenObject(obj) {
  Object.keys(obj).forEach(function objectForEach(key) {
    if (obj[key] && obj[key][0] && obj[key].length === 1) {
      obj[key] = obj[key][0];
    }

    if (typeof obj[key] === 'object') {
      return flattenObject(obj[key]);
    }
  });

  return obj;
}

function parseAttributes(assertion, tokenHandler, cb) {
  let profile = null;

  try {
    profile = tokenHandler.parse(assertion);
  } catch (e) {
    const error = new WrapError('An error occurred trying to parse assertion.');
    error.inner = e;

    cb(error);
    return;
  }

  cb(null, profile);
}

const randomId = () => {
  return '_' + crypto.randomBytes(10).toString('hex');
};

// Create SAML Response and sign it
const createSAMLResponse = async ({
  audience,
  issuer,
  acsUrl,
  claims,
  requestId,
  privateKey,
  publicKey,
}: {
  audience: string;
  issuer: string;
  acsUrl: string;
  claims: Record<string, any>;
  requestId: string;
  privateKey: string;
  publicKey: string;
}): Promise<string> => {
  const authDate = new Date();
  const authTimestamp = authDate.toISOString();

  authDate.setMinutes(authDate.getMinutes() - 5);
  const notBefore = authDate.toISOString();

  authDate.setMinutes(authDate.getMinutes() + 10);
  const notAfter = authDate.toISOString();

  const nodes = {
    'samlp:Response': {
      '@Destination': acsUrl,
      '@ID': randomId(),
      '@InResponseTo': requestId,
      '@IssueInstant': authTimestamp,
      '@Version': '2.0',
      '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
      '@xmlns:xs': 'http://www.w3.org/2001/XMLSchema',
      'saml:Issuer': {
        '@Format': 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        '#text': issuer,
      },
      'samlp:Status': {
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        'samlp:StatusCode': {
          '@Value': 'urn:oasis:names:tc:SAML:2.0:status:Success',
        },
      },
      'saml:Assertion': {
        '@ID': randomId(),
        '@IssueInstant': authTimestamp,
        '@Version': '2.0',
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        '@xmlns:xs': 'http://www.w3.org/2001/XMLSchema',
        'saml:Issuer': {
          '@Format': 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
          '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
          '#text': issuer,
        },
        'saml:Subject': {
          '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
          'saml:NameID': {
            '@Format': 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            '#text': claims.email,
          },
          'saml:SubjectConfirmation': {
            '@Method': 'urn:oasis:names:tc:SAML:2.0:cm:bearer',
            'saml:SubjectConfirmationData': {
              '@InResponseTo': requestId,
              '@NotOnOrAfter': notAfter,
              '@Recipient': acsUrl,
            },
          },
        },
        'saml:Conditions': {
          '@NotBefore': notBefore,
          '@NotOnOrAfter': notAfter,
          '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
          'saml:AudienceRestriction': {
            'saml:Audience': {
              '#text': audience,
            },
          },
        },
        'saml:AuthnStatement': {
          '@AuthnInstant': authTimestamp,
          '@SessionIndex': requestId,
          '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
          'saml:AuthnContext': {
            'saml:AuthnContextClassRef': {
              '#text': 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
            },
          },
        },
        'saml:AttributeStatement': {
          '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
          'saml:Attribute': Object.keys(claims.raw).map((attributeName) => {
            const attributeValue = claims.raw[attributeName];

            if (Array.isArray(attributeValue)) {
              return {
                '@Name': attributeName,
                '@NameFormat': 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified',
                'saml:AttributeValue': attributeValue.map((value) => {
                  return {
                    '@xmlns:xs': 'http://www.w3.org/2001/XMLSchema',
                    '@xmlns:xsi': 'http://www.w3.org/2001/XMLSchema-instance',
                    '@xsi:type': 'xs:string',
                    '#text': value,
                  };
                }),
              };
            }

            return {
              '@Name': attributeName,
              '@NameFormat': 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified',
              'saml:AttributeValue': {
                '@xmlns:xs': 'http://www.w3.org/2001/XMLSchema',
                '@xmlns:xsi': 'http://www.w3.org/2001/XMLSchema-instance',
                '@xsi:type': 'xs:string',
                '#text': attributeValue,
              },
            };
          }),
        },
      },
    },
  };

  const xml = xmlbuilder.create(nodes, { encoding: 'UTF-8' }).end();

  const signedAssertionXml = sign(xml, privateKey, publicKey, '//*[local-name(.)="Assertion"]');

  const signedXml = sign(
    signedAssertionXml,
    privateKey,
    publicKey,
    '/*[local-name(.)="Response" and namespace-uri(.)="urn:oasis:names:tc:SAML:2.0:protocol"]'
  );

  return signedXml;
};

export { createSAMLResponse, parse, validate, parseIssuer, WrapError };
