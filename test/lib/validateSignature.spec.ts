import { certToPEM, hasValidSignature, validateSignature } from '../../lib/validateSignature';
import { expect } from 'chai';
import xmlbuilder from 'xmlbuilder';

import crypto from 'crypto';
import { sign } from '../../lib/sign';

const ssoUrl =
  'https://dev-20901260.okta.com/app/dev-20901260_jacksondemo5225_1/exk3wth7ss1TKnAN15d7/sso/saml';
const entityID = 'https://saml.boxyhq.com';
const callbackUrl = 'http://localhost:5225/api/oauth/saml';

const signingKey =
  '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC+OW02UYdrA8aHlgcVmGT551Ft3Z83uRNCMNHHKGzVOARhm0xY4RhLya/o+sMz6I+rwvhk00ZNv9qQHXqXiP0tOn8gdjtL9Iw2OH7Jpe6VRvhmWq/0ts0YrDL33VjjoKwJgblFgV0s0XIb58qQa2Leif2KucFHtRkEMWaAaBzrUC7PpNVoV75zBzLkQ0H7ERm3haobE8hdFUR+pI+Nn6WiFbtrqedtV4vospd3m3LwmLIYCPdoMNl9/o578wjG03qLHOx9ewvR2GZa91T7z6th0Yb2q4g3oGWtO4+PiOiTVzNtcIyunGvbkCSFE5uTWohclkZFNupHeB9DwLHvrwytAgMBAAECggEBAJDF9/59MkkaCICsiBvBbihcCrdJEqJAMw4PRbkDZUEpbvwyS3rhZbJYf48bOnFJL/8TViS2Py1xNJC2PtURp05C1PoJwbtfFU821Bf4N4pZBzgvEPd4IMQEWo4WYk5rvENH/Y+OkzFG/keKs7oSYJ7p+pMYKKfAhpeQWWik1E2p2coaN0gFIyY1Jei22VTh/BjzNAxc3bI1F2tHUovo3EHJ4Ft2exYG9231JloHKPsxsPR/7BigDFFqaGYQyp3lxNvPSdH0UN+chfLZsCI5cG//qMeAAPHu9zdwOorSuHxB6kP69tPdFRTs6DaHVmSwsC+XpzoE4nXBWyM+6lnEuYECgYEA7676sYOiXJ6Y/epaDxZHdLTkPJK5YqJG1xmCFYGslkcbeYQyhpzQzAAzgxefPXhKcaFpEv2gvBbtGE7rxvjBSX4EVaeIcP+8bex6K3ZH0ND5EUFeg8EbZf4rkbqPexEocxn+2HZ/HhHNYvgLMeicKe4bcAIt0z/yTi3B0ufSJ/0CgYEAyyyCrJzCN7x4aOhlFmD3qwKyHRu0AszJY5xONO0A3ZjtKzOGqPcHwNZqq8yCgFTDvqkvicsqo9i/9+czC1MnyQ7hpG43+2JoemPq87uzlvkt0eck1ncyjeTK5ckpvRaiOFhtOWoIqpBGzL4iBPI5TxA3e9lYlHxJ3+KRQ1uW3nECgYA7YPIigCX9JB1q6mAdVLunIhlZGFBtKx65s0wS3+lN4Zfg5utNhhQENhiM5ZFBvUdUF1Tcq5DiiBt85jBrPr1D48BXKAYZWIHqCafKlKb+CIdryvILWg/bmLhahgl9x6ZpvYrxPYoIfQiQ+Dptxt7JVH/fo+qOZ000KQnXoi7iUQKBgE+Ayl2bNdCzmnaKwcvBBAlSE7qaNZWG5yNobZ3+RAFyrxPhpMcHa2xFOxag/0wSX0qDT8veyX+1+GCcgvfigUYG4bsDOjrPZkzGPpFDmOHx/cEObvbRS+IEbnT+g6uvaKkdyRfXay67KElD+XHwCwbqNJvtD+GCxTGrqeYut9mxAoGAabRuoqxlO/eZnxBYRb3aHTcn4bTaKvJm5ez2vyctgc01wScpigly4EWaVTy7LEJAQV+RbnlI3EARHnPc7Mr+brtXnLwinGRh5WZiU4oF+Wm6WFzTS0h47WjK4TmbKdr04P/3hkhT71sxc3VEfj9Hf4XiaAmJaUQ/LyPXHzapbuY=\n-----END PRIVATE KEY-----';
const publicKey =
  '-----BEGIN CERTIFICATE-----\nMIIC6jCCAdKgAwIBAgIBATANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDEw5Cb3h5SFEgSmFja3NvbjAcFw0yMjA0MDcxOTEyMTBaFwsxMjMxMTgzMDAwWjAZMRcwFQYDVQQDEw5Cb3h5SFEgSmFja3NvbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL45bTZRh2sDxoeWBxWYZPnnUW3dnze5E0Iw0ccobNU4BGGbTFjhGEvJr+j6wzPoj6vC+GTTRk2/2pAdepeI/S06fyB2O0v0jDY4fsml7pVG+GZar/S2zRisMvfdWOOgrAmBuUWBXSzRchvnypBrYt6J/Yq5wUe1GQQxZoBoHOtQLs+k1WhXvnMHMuRDQfsRGbeFqhsTyF0VRH6kj42fpaIVu2up521Xi+iyl3ebcvCYshgI92gw2X3+jnvzCMbTeosc7H17C9HYZlr3VPvPq2HRhvariDegZa07j4+I6JNXM21wjK6ca9uQJIUTm5NaiFyWRkU26kd4H0PAse+vDK0CAwEAAaM/MD0wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFI0tLXGuzcZi2eXNI3epHYJwreXQMA0GCSqGSIb3DQEBCwUAA4IBAQAEre2GfP/haRoQo0JYFKqXNsogR1++kFIebn9FTnb64+bDd5DRhV2pOAtAFIWUbm5+YeQIkBbAQmfPFX5OG6WgBSqgJCMpU7ekVwU/tExhxXFaTCRL39pMwLnsJ9R6NIy/WUKrTDW9VtyINE5OIL7lDZbejKbidIuOtdyJtlJrLtnVuhiLmNaZJo+kDKvHYKVmwdEXRMQ5OyR0f53MV4Kq/28dSeUQPe+qKovrcVk3F0J8h+aj/+1bU6VsBfrNSRq1dO/jQM6oIOUI68q3GNBeOCEcDGXpytX5C0HxVmNTz5/ybqB14hEhp343GIZ0/gbdAGmt90uJHoS9Xp4dI77j\n-----END CERTIFICATE-----';
const idPrefix = '_';
const authnXPath =
  '/*[local-name(.)="AuthnRequest" and namespace-uri(.)="urn:oasis:names:tc:SAML:2.0:protocol"]';
const identifierFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
const providerName = 'BoxyHQ';

function generateXML() {
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

  // if (isPassive) samlReq['samlp:AuthnRequest']['@IsPassive'] = true;

  // if (forceAuthn) {
  //   samlReq['samlp:AuthnRequest']['@ForceAuthn'] = true;
  // }

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
  return xml;
}

describe('validateSignature.ts', function () {
  it('certToPEM ok', function () {
    const value = certToPEM(publicKey);
    expect(publicKey).to.eqls(value);
  });

  it('hasValidSignature ok ', function () {
    const value = hasValidSignature(generateXML(), publicKey, 'null');
    expect(value.valid).to.be.equal(true);
    expect(value.calculatedThumbprint).to.be.equal('d730fc9342107b05032393d21cd5ef550150e06b');
  });

  it('validateSignature ok ', function () {
    expect(validateSignature(generateXML(), publicKey, 'null')).to.be.ok;
  });

  it('validateSignature public key not ok ', function () {
    try {
      const value = validateSignature(generateXML(), undefined, 'null');
      expect(value).to.be.equal(undefined);
    } catch (error) {
      expect(error).to.be.ok;
    }
  });
});
