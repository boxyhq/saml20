'use strict';

import { hasValidSignature, validateSignature, certToPEM } from './validateSignature';

import { request, parseSAMLRequest, decodeBase64 } from './request';
import { stripCertHeaderAndFooter, PubKeyInfo } from './cert';
import { createSAMLResponse, parse, validate, parseIssuer, WrapError } from './response';
import { parseMetadata, createIdPMetadataXML, createSPMetadataXML } from './metadata';
import { createPostForm } from './post';
import { sign } from './sign';
import { decryptXml } from './decrypt';
import { parseLogoutResponse, createLogoutRequest } from './logout';

export default {
  parseMetadata,
  createIdPMetadataXML,
  createSPMetadataXML,
  createSAMLResponse,
  request,
  parseSAMLRequest,
  decodeBase64,
  parse,
  validate,
  PubKeyInfo,
  certToPEM,
  stripCertHeaderAndFooter,
  createPostForm,
  sign,
  hasValidSignature,
  validateSignature,
  decryptXml,
  parseIssuer,
  WrapError,
  parseLogoutResponse,
  createLogoutRequest,
};
