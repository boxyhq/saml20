import crypto from 'crypto';
import xml2js from 'xml2js';
import xmlbuilder from 'xmlbuilder';

const parseLogoutResponse = async (
  rawResponse: string
): Promise<{
  id: string;
  issuer: string;
  status: string;
  destination: string;
  inResponseTo: string;
}> => {
  return new Promise((resolve, reject) => {
    xml2js.parseString(
      rawResponse,
      { tagNameProcessors: [xml2js.processors.stripPrefix] },
      (err: Error | null, { LogoutResponse }) => {
        if (err) {
          reject(err);
          return;
        }

        resolve({
          issuer: LogoutResponse.Issuer[0]._,
          id: LogoutResponse.$.ID,
          status: LogoutResponse.Status[0].StatusCode[0].$.Value,
          destination: LogoutResponse.$.Destination,
          inResponseTo: LogoutResponse.$.InResponseTo,
        });
      }
    );
  });
};

const createLogoutRequest = ({
  nameId,
  providerName,
  sloUrl,
}: {
  nameId: string;
  providerName: string;
  sloUrl: string;
}): { id: string; xml: string } => {
  const id = '_' + crypto.randomBytes(10).toString('hex');

  const xml: Record<string, any> = {
    'samlp:LogoutRequest': {
      '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
      '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
      '@ID': id,
      '@Version': '2.0',
      '@IssueInstant': new Date().toISOString(),
      '@Destination': sloUrl,
      'saml:Issuer': {
        '#text': providerName,
      },
      'saml:NameID': {
        '@Format': 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        '#text': nameId,
      },
    },
  };

  return {
    id,
    xml: xmlbuilder.create(xml).end({}),
  };
};

export { parseLogoutResponse, createLogoutRequest };
