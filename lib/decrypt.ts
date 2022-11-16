import { select } from 'xpath';
import * as xmlenc from 'xml-encryption';
import { parseFromString } from './utils';

const assertion = (xml: Document, encryptedAssertions: Node[], options) => {
  if (!Array.isArray(encryptedAssertions)) {
    throw new Error('Error Undefined Encrypted Assertion.');
  }
  if (encryptedAssertions.length !== 1) {
    throw new Error('Error Multiple Assertion.');
  }

  return xmlenc.decrypt(encryptedAssertions[0], { key: options.privateKey }, (err, res) => {
    if (err) {
      return new Error('Error Exception of Assertion Decryption.');
    }
    if (!res) {
      return new Error('Error Undefined Encryption Assertion.');
    }

    const assertionNode = parseFromString(res);
    xml.documentElement.removeChild(encryptedAssertions[0]);
    xml.documentElement.appendChild(assertionNode);

    return xml.toString();
  });
};
const decryptXml = (entireXML: string, options) => {
  if (!entireXML) {
    return new Error('Error Undefined Assertion.');
  }

  const xml = parseFromString(entireXML);

  const encryptedAssertions = select(
    "/*[contains(local-name(), 'Response')]/*[local-name(.)='EncryptedAssertion']",
    xml
  ) as Node[];

  if (encryptedAssertions.length >= 1) {
    return assertion(xml, encryptedAssertions, options);
  }

  return entireXML;
};

export { decryptXml };
