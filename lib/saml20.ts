import _ from 'lodash';

const nameIdentifierClaimType = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier';

function getClaims(attributes) {
  const claims = {};

  attributes.forEach(function attributesForEach(attribute) {
    const attributeName = attribute['@'].Name;

    claims[attributeName] = getProp(attribute, 'AttributeValue');
  });

  return claims;
}

function trimWords(phrase) {
  return phrase
    .split(' ')
    .map(function wordMapping(w) {
      return w.trim();
    })
    .filter(function wordFiltering(w) {
      return !!w;
    })
    .join(' ');
}

function getProp(obj, prop?: string) {
  let result = prop ? _.get(obj, prop) : obj;

  if (result && result._) {
    result = result._;
  }

  if (typeof result === 'string') {
    result = trimWords(result);

    return result;
  } else if (result instanceof Array) {
    result.forEach(function parseArrayItem(i, ix) {
      result[ix] = getProp(i);
    });

    return result;
  } else {
    return;
  }
}

const parse = (assertion) => {
  let claims = {};
  let attributes = _.get(assertion, 'AttributeStatement.Attribute');

  if (attributes) {
    attributes = attributes instanceof Array ? attributes : [attributes];
    claims = getClaims(attributes);
  }

  const subjectName = getProp(assertion, 'Subject.NameID');

  if (subjectName) {
    claims[nameIdentifierClaimType] = subjectName;
  }

  return {
    audience: getProp(assertion, 'Conditions.AudienceRestriction.Audience'),
    claims: claims,
    issuer: getProp(assertion, 'Issuer'),
    sessionIndex: getProp(assertion, 'AuthnStatement.@.SessionIndex'),
  };
};

const validateAudience = (assertion, realm) => {
  const audience = getProp(assertion, 'Conditions.AudienceRestriction.Audience');
  if (Array.isArray(realm)) {
    return realm.indexOf(audience) !== -1;
  }
  return audience === realm;
};

const validateExpiration = (assertion) => {
  const dteNotBefore = getProp(assertion, 'Conditions.@.NotBefore');
  let notBefore: any = new Date(dteNotBefore);
  notBefore = notBefore.setMinutes(notBefore.getMinutes() - 10); // 10 minutes clock skew

  const dteNotOnOrAfter = getProp(assertion, 'Conditions.@.NotOnOrAfter');
  let notOnOrAfter: any = new Date(dteNotOnOrAfter);
  notOnOrAfter = notOnOrAfter.setMinutes(notOnOrAfter.getMinutes() + 10); // 10 minutes clock skew

  const now = new Date();
  return !(now < notBefore || now > notOnOrAfter);
};

const getInResponseTo = (xml) => {
  return getProp(xml, 'Response.@.InResponseTo');
};

const saml20 = { getInResponseTo, validateExpiration, validateAudience, parse };

export default saml20;
