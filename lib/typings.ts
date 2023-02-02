export interface SAMLReq {
  ssoUrl?: string;
  entityID: string;
  callbackUrl: string;
  isPassive?: boolean;
  forceAuthn?: boolean;
  identifierFormat?: string;
  providerName?: string;
  signingKey: string;
  publicKey: string;
}

export interface SAMLProfile {
  audience: string;
  claims: Record<string, any>;
  issuer: string;
  sessionIndex: string;
}
