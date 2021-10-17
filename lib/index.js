'use strict';

var xml2js = require('xml2js');
var getVersion = require('./getVersion.js');
var validateSignature = require('./validateSignature.js');
var tokenHandlers = {
  '1.1': require('./saml11.js'),
  '2.0': require('./saml20.js')
};

var saml = module.exports;

saml.parse = function parse(rawAssertion, cb) {
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

saml.validate = function validate(rawAssertion, options, cb) {
  if (!rawAssertion) {
    cb(new Error('rawAssertion is required.'));
    return;
  }

  if (!options || (!options.publicKey && !options.thumbprint)) {
    cb(new Error('publicKey or thumbprint are options required.'));
    return;
  }

  var validId = null;

  try {
    validId = validateSignature(rawAssertion, options.publicKey, options.thumbprint);
  }
  catch (e) {
    var error = new Error('Invalid assertion.');
    error.inner = e;
    cb(error);
    return;
  }

  if (!validId) {
    cb(new Error('Invalid assertion signature.'));
    return;
  }

  parseXmlAndVersion(rawAssertion, function onParse(err, assertion, version, response) {
    if (err) {
      cb(err);
      return;
    }

    var tokenHandler = tokenHandlers[version];

    if (!options.bypassExpiration && !tokenHandler.validateExpiration(assertion)) {
      cb(new Error('Assertion is expired.'));
      return;
    }

    if (options.audience && !tokenHandler.validateAudience(assertion, options.audience)) {
      cb(new Error('Invalid audience.'));
      return;
    }

    if (options.inResponseTo && assertion.inResponseTo !== options.inResponseTo) {
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
        (
          response['@'].ID !== validId &&
          response['@'].Id !== validId &&
          response['@'].id !== validId
        )
      ) {
        cb(new Error('Invalid assertion. Possible assertion wrapping.'));
        return;
      }
    }

    parseAttributes(assertion, tokenHandler, cb);
  });
};

function parseXmlAndVersion(rawAssertion, cb) {
  var parser = new xml2js.Parser({
    attrkey: '@',
    charKey: '#',
    tagNameProcessors: [xml2js.processors.stripPrefix]
  });

  parser.parseString(rawAssertion, function onParse(err, xml) {
    if (err) {
      var error = new Error('An error occurred trying to parse XML assertion.');
      error.inner = err;
      cb(error);
      return;
    }

    xml = xmlBeautify(xml);

    var assertion = xml.Assertion || xml.Response && xml.Response.Assertion || xml.RequestSecurityTokenResponse && xml.RequestSecurityTokenResponse.RequestedSecurityToken && xml.RequestSecurityTokenResponse.RequestedSecurityToken.Assertion;
    // if we have an array of assertions then pick first element
    if (assertion[0]) {
      assertion = assertion[0];
    }
    var version = getVersion(assertion);
    var response = xml.Response;

    if (!version) {
      cb(new Error('SAML Assertion version not supported.'));
      return;
    }

    var tokenHandler = tokenHandlers[version];
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
  var profile = null;

  try {
    profile = tokenHandler.parse(assertion);
  } catch (e) {
    var error = new Error('An error occurred trying to parse assertion.');
    error.inner = e;

    cb(error);
    return;
  }

  cb(null, profile);
}
