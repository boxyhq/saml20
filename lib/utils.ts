const isSingleRootedXML = (xmlDoc: Document) =>
  Array.from(xmlDoc.childNodes as NodeListOf<Element>).filter(
    (n) => n.tagName != null && n.childNodes != null
  ).length === 1;

export { isSingleRootedXML };
