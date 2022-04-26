export interface SAMLReq {
  ssoUrl?: string;
  entityID: string;
  callbackUrl: string;
  isPassive?: boolean;
  forceAuthn?: boolean;
  identifierFormat?: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
  providerName?: 'BoxyHQ';
  signingKey: string;
  publicKey: string;
}

export interface SAMLProfile {
  audience: string;
  claims: Record<string, any>;
  issuer: string;
  sessionIndex: string;
}
