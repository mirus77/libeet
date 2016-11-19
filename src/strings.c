#include "globals.h"

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>

/***************************
 *
 * Global Namespaces
 *
 ****************************/
const xmlChar libeetWsseNs[] = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
const xmlChar libeetWsuNs[]  = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
const xmlChar libeetExcNs[]  = "http://www.w3.org/2001/10/xml-exc-c14n#";
const xmlChar libeetWsseNsPrefix[] = "wsse";
const xmlChar libeetWsuNsPrefix[] = "wsu";


/***************************
 *
 * Wsse Nodes
 *
 ****************************/

const xmlChar libeetNodeSecurity[]                        = "Security";
const xmlChar libeetNodeBinarySecurityToken[]             = "BinarySecurityToken";
const xmlChar libeetNodeSecurityTokenReference[]          = "SecurityTokenReference";
const xmlChar libeetNodeSecurityAttrValueType[]           = "ValueType";
const xmlChar libeetNodeSecurityAttrValueTypeValue[]          = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
const xmlChar libeetNodeWsuAttrIdName[]                   = "wsu:Id";
const xmlChar libeetNodeSecurityAttrEncodingType[]        = "EncodingType";
const xmlChar libeetNodeSecurityAttrEncodingTypeValue[]   = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";

/***************************
 *
 * XSD Schema
 *
 ****************************/
const xmlChar libeetSchema[]                               = "http://fs.mfcr.cz/eet/schema/v3";
const xmlChar libeetSoapEnvelopePrefix[] = "soap";
const xmlChar libeetSoapHeaderPrefix[] = "soap-env";
