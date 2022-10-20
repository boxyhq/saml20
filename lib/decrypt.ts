import { DOMParser } from '@xmldom/xmldom';
import { select } from 'xpath';
import * as xmlenc from '@authenio/xml-encryption';
import { countRootNodes } from './utils';

const dom = DOMParser;

const assertion = (xml: Document, encryptedAssertions: Node[], options) => {
  if (!Array.isArray(encryptedAssertions)) {
    throw new Error('Error Undefined Encrypted Assertion.');
  }
  if (encryptedAssertions.length !== 1) {
    throw new Error('Error Multiple Assertion.');
  }

  return xmlenc.decrypt(encryptedAssertions[0].toString(), { key: options.privateKey }, (err, res) => {
    if (err) {
      return new Error('Error Exception of Assertion Decryption.');
    }
    if (!res) {
      return new Error('Error Undefined Encryption Assertion.');
    }

    const assertionNode = new dom().parseFromString(res);
    xml.replaceChild(assertionNode, encryptedAssertions[0]);

    return xml.toString();
  });
};
const decryptXml = (entireXML: string, options) => {
  if (!entireXML) {
    return new Error('Error Undefined Assertion.');
  }

  const xml = new dom().parseFromString(entireXML);

  const rootNodeCount = countRootNodes(xml);

  if (rootNodeCount > 1) {
    throw new Error('multirooted xml not allowed.');
  }

  if (rootNodeCount === 0) {
    throw new Error('Invalid assertion.');
  }

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
