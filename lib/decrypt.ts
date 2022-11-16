import { DOMParser } from '@xmldom/xmldom';
import { select } from 'xpath';
import * as xmlenc from 'xml-encryption';
import { countRootNodes } from './utils';

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

    const assertionNode = new DOMParser().parseFromString(res);
    xml.documentElement.removeChild(encryptedAssertions[0]);
    xml.documentElement.appendChild(assertionNode);

    return xml.toString();
  });
};
const decryptXml = (entireXML: string, options) => {
  if (!entireXML) {
    return new Error('Error Undefined Assertion.');
  }

  const errors = {};
  let multiRootErrFound = false;
  const errorHandler = (key, msg) => {
    if (!errors[key]) errors[key] = [];
    if (msg.indexOf('Only one element can be added and only after doctype')) {
      if (!multiRootErrFound) {
        multiRootErrFound = true;
        errors[key].push(msg);
      }
    } else {
      errors[key].push(msg);
    }
  };

  const xml = new DOMParser({ errorHandler }).parseFromString(entireXML);

  Object.keys(errors).forEach((key) => {
    if (errors[key].indexOf('Only one element can be added and only after doctype')) {
      throw new Error('multirooted xml not allowed.');
    }
  });

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
