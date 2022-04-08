'use strict';

import xml2js from 'xml2js';
import getVersion from './getVersion';
import validateSignature from './validateSignature';
import saml20 from './saml20';

const tokenHandlers = {
  '2.0': saml20,
};

class WrapError extends Error {
  inner?: any;
}

const parse = function parse(rawAssertion, cb) {
  if (!rawAssertion) {
    cb(new Error('rawAssertion is required.'));
    return;
  }

  parseXmlAndVersion(rawAssertion, function onParse(err, assertion, version) {
    if (err) {
      cb(err);
      return;
    }

    parseAttributes(assertion, tokenHandlers[version], cb);
  });
};

const validate = function validate(rawAssertion, options, cb) {
  if (!rawAssertion) {
    cb(new Error('rawAssertion is required.'));
    return;
  }

  if (!options || (!options.publicKey && !options.thumbprint)) {
    cb(new Error('publicKey or thumbprint are options required.'));
    return;
  }

  let validId = null;

  try {
    validId = validateSignature(
      rawAssertion,
      options.publicKey,
      options.thumbprint
    );
  } catch (e) {
    let error = new WrapError('Invalid assertion.');
    error.inner = e;
    cb(error);
    return;
  }

  if (!validId) {
    cb(new Error('Invalid assertion signature.'));
    return;
  }

  parseXmlAndVersion(
    rawAssertion,
    function onParse(err, assertion, version, response) {
      if (err) {
        cb(err);
        return;
      }

      const tokenHandler = tokenHandlers[version];

      if (
        !options.bypassExpiration &&
        !tokenHandler.validateExpiration(assertion)
      ) {
        cb(new Error('Assertion is expired.'));
        return;
      }

      if (
        options.audience &&
        !tokenHandler.validateAudience(assertion, options.audience)
      ) {
        cb(new Error('Invalid audience.'));
        return;
      }

      if (
        options.inResponseTo &&
        assertion.inResponseTo !== options.inResponseTo
      ) {
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
          (response['@'].ID !== validId &&
            response['@'].Id !== validId &&
            response['@'].id !== validId)
        ) {
          cb(new Error('Invalid assertion. Possible assertion wrapping.'));
          return;
        }
      }

      parseAttributes(assertion, tokenHandler, cb);
    }
  );
};

function parseXmlAndVersion(rawAssertion, cb) {
  const parser = new xml2js.Parser({
    attrkey: '@',
    charKey: '#',
    tagNameProcessors: [xml2js.processors.stripPrefix],
  });

  parser.parseString(rawAssertion, function onParse(err, xml) {
    if (err) {
      let error = new WrapError(
        'An error occurred trying to parse XML assertion.'
      );
      error.inner = err;
      cb(error);
      return;
    }

    xml = xmlBeautify(xml);

    let assertion =
      xml.Assertion ||
      (xml.Response && xml.Response.Assertion) ||
      (xml.RequestSecurityTokenResponse &&
        xml.RequestSecurityTokenResponse.RequestedSecurityToken &&
        xml.RequestSecurityTokenResponse.RequestedSecurityToken.Assertion);
    // if we have an array of assertions then pick first element
    if (assertion && assertion[0]) {
      assertion = assertion[0];
    }

    if (!assertion) {
      cb(new Error('Invalid assertion.'));
      return;
    }

    const version = getVersion(assertion);
    const response = xml.Response;

    if (!version) {
      cb(new Error('SAML Assertion version not supported.'));
      return;
    }

    const tokenHandler = tokenHandlers[version];
    assertion.inResponseTo = tokenHandler.getInResponseTo(xml);

    cb(null, assertion, version, response);
  });
}

function xmlBeautify(obj) {
  Object.keys(obj).forEach(function objectForEach(key) {
    if (obj[key] && obj[key][0] && obj[key].length === 1) {
      obj[key] = obj[key][0];
    }

    if (typeof obj[key] === 'object') {
      return xmlBeautify(obj[key]);
    }
  });

  return obj;
}

function parseAttributes(assertion, tokenHandler, cb) {
  let profile = null;

  try {
    profile = tokenHandler.parse(assertion);
  } catch (e) {
    let error = new WrapError('An error occurred trying to parse assertion.');
    error.inner = e;

    cb(error);
    return;
  }

  cb(null, profile);
}

export default { parse, validate };
