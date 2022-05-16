import { DOMParser } from '@xmldom/xmldom';
import { select } from 'xpath';
import * as xmlenc from '@authenio/xml-encryption';

const dom = DOMParser;
const privateKey =
  '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDPItnFnMX5NTNhr77sEMLl6Ak5lmjv4BSPxL4mtA6Qj0h7NmFxGmo8+YG5qIznQfcIEDVRcaqrjsci5X9MxahCKn830X1BrFaHWlshZ/5YzBH4mFKIscgH3MAOFLS88DhZQ81QIJ8NS1Rvn3Adr+YJeSFg6MLjdpHQp9GqkjZ7bdIsXTWOQCV6HFVSxdhA3MQl4w4GgiGrugScguvrTd05drcsgOTf3a5fZk6S/AMY3rbuSAyNMVWhS6oOZUvxCZy9WWvyFCd9Rlqas2tjII9NN++eJBkqmJbBLw9uN34qLuD41XcDPp/qCDRKqBv5m+lxjFVGfDsHHOoA42F4kH8fAgMBAAECggEAGVxS/XbsZk61M8iov45tzmhSeNKJlpUA73lPLr3s6pYgcbV+yLJLP5vs3iZc2hOhg0M4w/f+xXJ9vzAKHgQ1TaSWXucvRtMq5PeTIMvywDx8FsvPjxz1OME2YoL2fguLWqKKiLz1vFL0y5XhzEC1EYPbKlpVQjRKNhnV+eRc90+KbAGpIf+6YBErn5cr6Antn4HrtbSI83n/kAbCcZjA2QJnIxuMy2JzwAu6TJjTIwKk/pg4XykHfFTIBIPHd8lyc+tE255N7LmdiWj1RMuABjNVQIUu5RHx8ZlFVD0eX2HgSv2P9CFlroy7KEjeMQOHmDFBksJ7WRdqCFrWvT5xAQKBgQDy7thLoPW0ilSIuuUV4mb7IaqHtBAPPxjfilPWdRXY1q+1RGav+7RRU0V9MHQz7BQsRi8GIEvYTyX2OK/WAhN8u++uzxisKooQad9+g5b33fkhWfDmwOJjbj0RGN9NvBlYx4A6T6THQQlnLW2SjouEECUDPGx6vkF57hKH5gaAUQKBgQDaRxZ9FJHEZ6ChbzTgAFkEsgzG6IP7MpjhXo1xFFyxYOMUG5LvgGOVoTOhY/ZVj6M8Qpp2PN4hhVAwF7GBTiJ23oTE1ETwomIetFJO9HEwxq7/qK9Ca7oPemdve0vayG3aemX9GB7D/OPyeT1kmrzqPSIYe8RDGxUFZJcyItYcbwKBgC324xXsLpEqWzRDqHSrkbCSfiGPADriRWKGWbaKEMgmVriFaKiDh2qbxtoZAOOSF38JCHywP6l90ED2GM71NZq0NHVu2cw5gEX6wj69xyK+7RRSYDJI7IzDnupNOnMK1ADoPmrKBvNsassK3WCNd/hU1av3Es9mkBzx3q+35iMBAoGAF8wSRpa8gaYunAsMv7MqAVoMDI+C/Br7Ee8GCqMGrAv9Fc8fyN69fK2zfE/ypkdfq40zW9qs+QiYwnWC068aEM2XugHOdlGt0t0j8Bm0UXYH1DWmzd4CzfcxWbUegv7BA0W+4sYDbKigjWnsaJB6MityEStFLW/BbfIWjc/Aeh8CgYEAt8qj2xAMT7KYo2ggAEBSV6hvBrBKXjpp91yXwt8fJfe2TN3VLbA1tlCjiPP/rjyUvEGfsOuqLHNtJECmvwgkLnoWMKVeusjKf+NPc2ZCEw0RMoeAYPUy5GZGOcCMfylvpND2T+h/7BTFUSJIQkDIPagHiLzEuH4r/NxhqZcYGM0=\n-----END PRIVATE KEY-----';
const options = {
  encPrivateKey: privateKey,
};
/**
 * @desc Decrypt the assertion section in Response
 * @param  {string} type             only accept SAMLResponse to proceed decryption
 * @param  {Entity} here             this entity
 * @param  {Entity} from             from the entity where the message is sent
 * @param {string} entireXML         response in xml string format
 * @return {function} a promise to get back the entire xml with decrypted assertion
 */
const assertion = function assertion(here, entireXML: string) {
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

  try {
    return xmlenc.decrypt(encryptedAssertions[0].toString(), { key: here.encPrivateKey }, (err, res) => {
      if (err) {
        // console.error(err);
        return new Error('Error Exception of Assertion Decryption.');
      }
      if (!res) {
        return new Error('Error Undefined Encryption Assertion.');
      }

      const assertionNode = new dom().parseFromString(res);
      xml.replaceChild(assertionNode, encryptedAssertions[0]);

      return xml.toString();
    });
  } catch (error) {
    console.log(error);
  }
};
const decryptXml = function decryptXml(entireXML: string) {
  let rawAssertionNew = entireXML;
  try {
    const xml = new dom().parseFromString(entireXML);
    const encryptedAssertions = select(
      "/*[contains(local-name(), 'Response')]/*[local-name(.)='EncryptedAssertion']",
      xml
    ) as Node[];

    if (encryptedAssertions.length >= 1) {
      rawAssertionNew = assertion(options, entireXML);
      return rawAssertionNew;
    }
  } catch (error) {
    console.log('error inside encryption ');
    console.log(error);
    throw new Error('Decryption Error.');
  }
  return rawAssertionNew;
};

export { assertion, decryptXml };
