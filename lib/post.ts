const createPostForm = (postUrl: string, params: { name: string; value: string }[]) => {
  const parr = (params || []).map(({ name, value }) => {
    return `<input type="hidden" name="${name}" value="${value.replace(/"/g, '&quot;')}"/>`;
  });

  const formElements = [
    '<!DOCTYPE html>',
    '<html>',
    '<head>',
    '<meta charset="utf-8">',
    '<meta http-equiv="x-ua-compatible" content="ie=edge">',
    '</head>',
    '<body onload="document.forms[0].submit()">',
    '<noscript>',
    '<p>Note: Since your browser does not support JavaScript, you must press the Continue button once to proceed.</p>',
    '</noscript>',
    `<form method="post" action="${encodeURI(postUrl)}">`,
  ]
    .concat(...parr)
    .concat(
      ...[
        '<input type="submit" value="Continue" />',
        '</form>',
        '<script>document.forms[0].style.display="none";</script>',
        '</body>',
        '</html>',
      ]
    );

  return formElements.join('\r\n');
};

export { createPostForm };
