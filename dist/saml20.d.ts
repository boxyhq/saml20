export function parse(assertion: any): {
    audience: any;
    claims: {};
    issuer: any;
    sessionIndex: any;
};
export function validateAudience(assertion: any, realm: any): boolean;
export function validateExpiration(assertion: any): boolean;
export function getInResponseTo(xml: any): any;
