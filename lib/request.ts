import xmlbuilder from 'xmlbuilder';
import { SAMLReq } from './typings';
import crypto from 'crypto';
import { sign } from './sign';

const idPrefix = '_';
const authnXPath =
  '/*[local-name(.)="AuthnRequest" and namespace-uri(.)="urn:oasis:names:tc:SAML:2.0:protocol"]';

const request = ({
  ssoUrl,
  entityID,
  callbackUrl,
  isPassive = false,
  forceAuthn = false,
  identifierFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  providerName = 'BoxyHQ',
  signingKey,
  publicKey,
}: SAMLReq): { id: string; request: string } => {
  const id = idPrefix + crypto.randomBytes(10).toString('hex');
  const date = new Date().toISOString();

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const samlReq: Record<string, any> = {
    'samlp:AuthnRequest': {
      '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
      '@ID': id,
      '@Version': '2.0',
      '@IssueInstant': date,
      '@ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      '@Destination': ssoUrl,
      'saml:Issuer': {
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        '#text': entityID,
      },
    },
  };

  if (isPassive) samlReq['samlp:AuthnRequest']['@IsPassive'] = true;

  if (forceAuthn) {
    samlReq['samlp:AuthnRequest']['@ForceAuthn'] = true;
  }

  samlReq['samlp:AuthnRequest']['@AssertionConsumerServiceURL'] = callbackUrl;

  samlReq['samlp:AuthnRequest']['samlp:NameIDPolicy'] = {
    '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
    '@Format': identifierFormat,
    '@AllowCreate': 'true',
  };

  if (providerName != null) {
    samlReq['samlp:AuthnRequest']['@ProviderName'] = providerName;
  }

  let xml = xmlbuilder.create(samlReq).end({});
  if (signingKey) {
    xml = sign(xml, signingKey, publicKey, authnXPath);
  }

  return {
    id,
    request: xml,
  };
};

export { request };
