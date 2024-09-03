import { DOMParser, MIME_TYPE } from '@xmldom/xmldom';
import crypto from 'crypto';

const countRootNodes = (xmlDoc: Document) => {
  const rootNodes = Array.from(xmlDoc.childNodes as NodeListOf<Element>).filter(
    (n) => n.tagName != null && n.childNodes != null
  );
  return rootNodes.length;
};

const parseFromString = (xmlString: string) => {
  const errors: string[] = [];
  let multiRootErrFound = false;
  const onError = (level, msg, context) => {
    if (msg.indexOf('Only one element can be added and only after doctype')) {
      if (!multiRootErrFound) {
        multiRootErrFound = true;
        errors.push(msg);
      }
    } else if (level !== 'warn') {
      errors.push(msg);
    }
  };

  const xml = new DOMParser({ onError }).parseFromString(xmlString, MIME_TYPE.XML_APPLICATION);

  if (multiRootErrFound) {
    throw new Error('multirooted xml not allowed.');
  } else if (errors.length > 0) {
    throw new Error('Invalid XML.');
  }

  const rootNodeCount = countRootNodes(xml);

  if (rootNodeCount > 1) {
    throw new Error('multirooted xml not allowed.');
  }

  if (rootNodeCount === 0) {
    throw new Error('Invalid assertion.');
  }

  return xml;
};

const thumbprint = (cert: string) => {
  const shasum = crypto.createHash('sha1');
  const bin = Buffer.from(cert, 'base64').toString('binary');
  shasum.update(bin);
  return shasum.digest('hex');
};

const getAttribute = <TDefault = unknown>(value: any, path: string, defaultValue?: TDefault): TDefault => {
  const segments = path.split(/[\.\[\]]/g); // eslint-disable-line no-useless-escape
  let current: any = value;
  for (const key of segments) {
    if (current === null) return defaultValue as TDefault;
    if (current === undefined) return defaultValue as TDefault;
    const dequoted = key.replace(/['"]/g, '');
    if (dequoted.trim() === '') continue;
    current = current[dequoted];
  }
  if (current === undefined) return defaultValue as TDefault;
  return current;
};

export { parseFromString, thumbprint, getAttribute };
