const mapping = [
  {
    attribute: 'id',
    schema: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier',
  },
  {
    attribute: 'email',
    schema: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
  },
  {
    attribute: 'firstName',
    schema: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
  },
  {
    attribute: 'lastName',
    schema: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
  },
] as const;

type attributes = typeof mapping[number]['attribute'];
type schemas = typeof mapping[number]['schema'];

const map = (claims: Record<attributes | schemas, unknown>) => {
  const profile = {
    raw: claims,
  };

  mapping.forEach((m) => {
    if (claims[m.attribute]) {
      profile[m.attribute] = claims[m.attribute];
    } else if (claims[m.schema]) {
      profile[m.attribute] = claims[m.schema];
    }
  });

  return profile;
};

export default { map };
