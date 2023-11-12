import { certToPEM, hasValidSignature, validateSignature } from '../../lib/validateSignature';
import { expect } from 'chai';
import xmlbuilder from 'xmlbuilder';

import crypto from 'crypto';
import fs from 'fs';
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

const validResponseWithMultiCertsMetadata = fs
  .readFileSync('./test/assets/saml20.validResponse.multicertsMetadata.xml')
  .toString();

const multiPublicKey = `MIIDczCCAlugAwIBAgIUE4RU7Pwiw58ZifnjQOXVg6ytNWowDQYJKoZIhvcNAQEL
  BQAwSDELMAkGA1UEBhMCSU4xEzARBgNVBAgMClNvbWUtU3RhdGUxDzANBgNVBAoM
  BkJveHlIUTETMBEGA1UEAwwKYm94eWhxLmNvbTAgFw0yMzExMTIxMDQ1MzdaGA8z
  MDIzMDMxNTEwNDUzN1owSDELMAkGA1UEBhMCSU4xEzARBgNVBAgMClNvbWUtU3Rh
  dGUxDzANBgNVBAoMBkJveHlIUTETMBEGA1UEAwwKYm94eWhxLmNvbTCCASIwDQYJ
  KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMkwF6oPPd3Fn3AXC8K8h+q0uRgRoJim
  HASKmwzXZZjqb2DN0isLNvbLlcB3mTmfQMhKH4yLPE5PHoDJ83olgILkB6Y3txgG
  QJ48sIEeYiGCs+le4UnD44oL04fQCpkIImcFiHM/tr9kSnQsjF7tLn6GVZJKUU56
  84mrOACHr3LDZkypLxjiYMoM9aojS3yw97AIJSyhmkpowuqdtmK/T5o4pnTNgXTB
  XYPoGx/6aqoFVxAjh7ZuUzeHAMGHZlxT0e6K7nKSPoFKDbfDQoAwbq6B1BRNklSX
  4dz6MkmQAGqMnKBWNbiF2MAnt5dvIXInlafQ3Ypbw/bJ4uHw6L+RjGcCAwEAAaNT
  MFEwHQYDVR0OBBYEFHyOsXZSwmNqljrM6LmWFWr0nUsvMB8GA1UdIwQYMBaAFHyO
  sXZSwmNqljrM6LmWFWr0nUsvMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
  BQADggEBALFfujo7fMqszjEg7Gla3FthO82/D+7mFKSGt04ZJfxlwuujTpI8u04g
  LWNFV6uHLNNlxesdd1r9JtlXAHN4pDk06TEidz1oOO1rBWVDBajrO1wME99EqOAj
  Q64SOFhkpw9Yd5L47SnxC3rQPsgeol+BJwosXcPG4OXjK5JisQGdakEJh8GLnE5u
  7QK5eFf84Qro6HthD+YsA0pPFDzh4TtSpm/yYDYRvKAfqh4a2uqwJDHJ8oxz5d37
  4eXJ/Zy78JiYM4PUnPMKABsqcUZv5vsuV5HPO4ODtcGFRY1EoSXcMxz0jkUipe+Z
  wmF8r5aO5sSGd+KOi2O/ja9VV4UzGD8=,MIIDczCCAlugAwIBAgIUOJZExQRTahl1DA9raMp0G6vCkHwwDQYJKoZIhvcNAQEL
  BQAwSDELMAkGA1UEBhMCSU4xEzARBgNVBAgMClNvbWUtU3RhdGUxDzANBgNVBAoM
  BkJveHlIUTETMBEGA1UEAwwKYm94eWhxLmNvbTAgFw0yMzExMTIxMTEwMDNaGA8z
  MDIzMDMxNTExMTAwM1owSDELMAkGA1UEBhMCSU4xEzARBgNVBAgMClNvbWUtU3Rh
  dGUxDzANBgNVBAoMBkJveHlIUTETMBEGA1UEAwwKYm94eWhxLmNvbTCCASIwDQYJ
  KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMWZyyDK9/I3Pic2TCnckbdVG/PIknyk
  YszbA+87q/MWlBA/vX2DogUw6UapZ07r6kxYRyMg/7VlJNP5rZXowv0LEpfpdAth
  8O7TomyEbwhl4u/8CcCbRvihkQtr1DFlHBYVSC7znkpeS1iYwfsDKhZc5NHmplG5
  +dERS71rtWqxb9hySPcX2CUJOvLjeC6uhTux5ers33963qnQzEsOuBRvcUT6TU7Y
  4WjzMycAjtsfT9r5y5Lhv9DpsIpVSRQ1MCLHCAeD1BerUZaebTonbsEA1EHk4vux
  FmjvlrNp4hh2zrtGt7yZO2cAzcNmloq+JmZ/7Yeb5CAhCaXIXFBBsh0CAwEAAaNT
  MFEwHQYDVR0OBBYEFLb5bLFbrOVXMAT5YnsQLSkPL3AyMB8GA1UdIwQYMBaAFLb5
  bLFbrOVXMAT5YnsQLSkPL3AyMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
  BQADggEBAKJFOBEouNp2AJicbA3Lmb4vVJfwP9h8LGqHV3TZHhlEblmBQNEoLyLO
  z7XhIy1/5LyGb7b/o0LAoC1RxH/6GiHcIKt4/DS7dOfrpcNkHXAUHVFZ1LfFtBHc
  zIZTXKWNiFLqz3nTaKS3dqmnZMsoWDuRpE4kwR5tT+zB492nnfH7XGICQDojQ1DN
  NDvfSxFNmjcEuabxM9VGdsX6xOiClZBJwJBixj74EYPeeVOPbOEQfQZchX8xB3u5
  2knHSNiamr0NJ4GA44hIoCADW2G6W2+A4gFNnA6UYFlaijMWqb/XSNlbkYZD6OkG
  9Xa5bTycscrxF6+S3n5z2yGft52wBe4=`;

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
    const value = hasValidSignature(generateXML(), publicKey, null);
    expect(value.valid).to.be.equal(true);
  });

  it('validateSignature ok ', function () {
    expect(validateSignature(generateXML(), publicKey, null)).to.be.ok;
  });

  it('validate Response signature multicert metadata', function () {
    const value = validateSignature(validResponseWithMultiCertsMetadata, multiPublicKey, null);
    expect(value).to.be.ok;
  });

  it('validateSignature public key not ok ', function () {
    try {
      const value = validateSignature(generateXML(), undefined, 'null');
      expect(value).to.be.equal(undefined);
    } catch (error) {
      expect(error).to.be.ok;
    }
  });

  it('must not validateSignature ok if cert and thumbprints provided and if key info has unknown cert', function () {
    const SAML_RESPONSE_WITH_UNKOWN_CERT_AT_KEY_INFO = `
<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_1" Version="2.0" IssueInstant="1900-01-01T01:01:00Z" Destination="https://acs-endpoint" InResponseTo="in_response_to">
    <saml:Issuer>issuer</saml:Issuer>
    <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
        <SignedInfo>
            <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <Reference URI="#_1">
                <Transforms>
                    <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                </Transforms>
                <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <DigestValue>5pCdjXFqMlPhoJATgpr2JIOrgxozccaZ0Zadp+nTwNU=</DigestValue>
            </Reference>
        </SignedInfo>
        <SignatureValue>AitFP4fhZVPMeJhnpCGLUiURGfBPiCVGPBT8G0UFRsBJ92nuqZIVvYeKqp8K2jsM
EaSKMhVGEHw31emtYnpfupRrJLEyhGgowJTNxjxDKHp8Q7coVdfM+zXAwiLtUlsg
X/bcWnef6z80FNy7cB0T7/S4CN/YQfDq6WFPePyx8q8=</SignatureValue>
        <KeyInfo>
            <X509Data>
                <X509Certificate>MIIBxDCCAW6gAwIBAgIQxUSXFzWJYYtOZnmmuOMKkjANBgkqhkiG9w0BAQQFADAW
MRQwEgYDVQQDEwtSb290IEFnZW5jeTAeFw0wMzA3MDgxODQ3NTlaFw0zOTEyMzEy
MzU5NTlaMB8xHTAbBgNVBAMTFFdTRTJRdWlja1N0YXJ0Q2xpZW50MIGfMA0GCSqG
SIb3DQEBAQUAA4GNADCBiQKBgQC+L6aB9x928noY4+0QBsXnxkQE4quJl7c3PUPd
Vu7k9A02hRG481XIfWhrDY5i7OEB7KGW7qFJotLLeMec/UkKUwCgv3VvJrs2nE9x
O3SSWIdNzADukYh+Cxt+FUU6tUkDeqg7dqwivOXhuOTRyOI3HqbWTbumaLdc8juf
z2LhaQIDAQABo0swSTBHBgNVHQEEQDA+gBAS5AktBh0dTwCNYSHcFmRjoRgwFjEU
MBIGA1UEAxMLUm9vdCBBZ2VuY3mCEAY3bACqAGSKEc+41KpcNfQwDQYJKoZIhvcN
AQEEBQADQQAfIbnMPVYkNNfX1tG1F+qfLhHwJdfDUZuPyRPucWF5qkh6sSdWVBY5
sT/txBnVJGziyO8DPYdu2fPMER8ajJfl</X509Certificate>
            </X509Data>
        </KeyInfo>
    </Signature>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_2" Version="2.0" IssueInstant="1900-01-01T01:01:00Z">
        <saml:Issuer>issuer</saml:Issuer>
        <saml:Subject>
            <saml:NameID SPNameQualifier="audience" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">some_name_id</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData NotOnOrAfter="8980-01-01T01:01:00Z" Recipient="https://acs-endpoint" InResponseTo="in_response_to"/>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="1900-01-01T01:00:00Z" NotOnOrAfter="8980-01-01T01:01:00Z">
            <saml:AudienceRestriction>
                <saml:Audience>audience</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="1900-01-01T01:01:00Z" SessionNotOnOrAfter="8980-01-01T01:01:00Z" SessionIndex="session_index">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
    </saml:Assertion>
</samlp:Response>
`;
    // NOTE: validateSignature's publicKey and certThumbprint are both provided
    // NOTE2: response is signed with
    // https://raw.githubusercontent.com/node-saml/xml-crypto/v4.1.0/test/static/client.pem
    // which cert is
    // https://raw.githubusercontent.com/node-saml/xml-crypto/v4.1.0/test/static/client_public.pem
    // i.e. validateSignature SHOULD NOT return id value because it is signed with unknown
    // key
    try {
      validateSignature(
        SAML_RESPONSE_WITH_UNKOWN_CERT_AT_KEY_INFO,
        publicKey,
        'd730fc9342107b05032393d21cd5ef550150e06b'
      );
    } catch (error) {
      expect(error).to.be.ok;
    }
  });
});
