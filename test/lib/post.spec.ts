import * as saml from '../../lib/post';
import { expect } from 'chai';
describe('post.ts', function () {
  it('Should validate creation of post form', function (done) {
    const relayState = 'boxyhq_jackson_17b723c56a2fdc4e94f5e5fa792f89e3';
    const samlRequest =
      'PHNhbWxwOkxvZ291dFJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c';
    const postUrl = 'https://auth0.com/samlp';

    const form = saml.createPostForm(postUrl, relayState, {
      name: 'SAMLRequest',
      value: samlRequest,
    });
    expect(form.includes(`<form method="post" action="${encodeURI(postUrl)}">`)).to.be.ok;
    expect(form.includes(`<input type="hidden" name="RelayState" value="${relayState}"/>`)).to.be.ok;
    expect(form.includes(`<input type="hidden" name="SAMLRequest" value="${samlRequest}"/>`)).to.be.ok;
    expect(form.includes(`<input type="submit" value="Continue" />`)).to.be.ok;
    done();
  });
});
