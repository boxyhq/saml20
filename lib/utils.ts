import { DOMParser } from '@xmldom/xmldom';

const countRootNodes = (xmlDoc: Document) => {
  const rootNodes = Array.from(xmlDoc.childNodes as NodeListOf<Element>).filter(
    (n) => n.tagName != null && n.childNodes != null
  );
  return rootNodes.length;
};

const parseFromString = (xmlString: string) => {
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

  const xml = new DOMParser({ errorHandler }).parseFromString(xmlString);

  if (multiRootErrFound) {
    throw new Error('multirooted xml not allowed.');
  } else if (Object.keys(errors).length > 0) {
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

export { parseFromString };
