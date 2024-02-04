'use strict';

import { hasValidSignature, validateSignature, certToPEM } from './validateSignature';

import { request, parseSAMLRequest, decodeBase64 } from './request';
import { stripCertHeaderAndFooter, PubKeyInfo } from './cert';
import { parse, validate, parseIssuer, WrapError } from './response';
import { parseMetadata } from './metadata';
import { createPostForm } from './post';
import { sign } from './sign';
import { decryptXml } from './decrypt';
import { parseLogoutResponse } from './logout';

export default {
  parseMetadata,
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
};
