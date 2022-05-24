import { DOMParser } from '@xmldom/xmldom';
import { select } from 'xpath';
import * as xmlenc from '@authenio/xml-encryption';

const dom = DOMParser;

/**
 * @desc Decrypt the assertion section in Response
 * @param  {string} type             only accept SAMLResponse to proceed decryption
 * @param  {Entity} here             this entity
 * @param  {Entity} from             from the entity where the message is sent
 * @param {string} entireXML         response in xml string format
 * @return {function} a promise to get back the entire xml with decrypted assertion
 */
const assertion = (here, entireXML: string) => {
  // Implement decryption first then check the signature
  if (!entireXML) {
    return new Error('Error Undefined Assertion.');
  }
  // Perform encryption depends on the setting of where the message is sent, default is false

  const xml = new dom().parseFromString(entireXML);
  const encryptedAssertions = select(
    "/*[contains(local-name(), 'Response')]/*[local-name(.)='EncryptedAssertion']",
    xml
  ) as Node[];

  if (!Array.isArray(encryptedAssertions)) {
    throw new Error('Error Undefined Encrypted Assertion.');
  }
  if (encryptedAssertions.length !== 1) {
    throw new Error('Error Multiple Assertion.');
  }

  return xmlenc.decrypt(encryptedAssertions[0].toString(), { key: here.privateKey }, (err, res) => {
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
  let rawAssertionNew = entireXML;

  const xml = new dom().parseFromString(entireXML);
  const encryptedAssertions = select(
    "/*[contains(local-name(), 'Response')]/*[local-name(.)='EncryptedAssertion']",
    xml
  ) as Node[];

  if (encryptedAssertions.length >= 1) {
    rawAssertionNew = assertion(options, entireXML);
    return rawAssertionNew;
  }

  return rawAssertionNew;
};

export { assertion, decryptXml };
