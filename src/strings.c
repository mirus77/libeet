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
const xmlChar libeetSoap11Ns[] = "http://schemas.xmlsoap.org/soap/envelope/";
const xmlChar libeetSoap12Ns[] = "http://www.w3.org/2002/06/soap-envelope";


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

#ifndef LIBEET_NO_SOAP
/*************************************************************************
 *
 * SOAP 1.1/1.2 strings
 *
 ************************************************************************/
const xmlChar libeetNodeEnvelope[] = "Envelope";
const xmlChar libeetNodeHeader[] = "Header";
const xmlChar libeetNodeBody[] = "Body";
const xmlChar libeetNodeFault[] = "Fault";
const xmlChar libeetNodeFaultCode[] = "faultcode";
const xmlChar libeetNodeFaultString[] = "faultstring";
const xmlChar libeetNodeFaultActor[] = "faultactor";
const xmlChar libeetNodeFaultDetail[] = "detail";
const xmlChar libeetNodeCode[] = "Code";
const xmlChar libeetNodeReason[] = "Reason";
const xmlChar libeetNodeNode[] = "Node";
const xmlChar libeetNodeRole[] = "Role";
const xmlChar libeetNodeDetail[] = "Detail";
const xmlChar libeetNodeValue[] = "Value";
const xmlChar libeetNodeSubcode[] = "Subcode";
const xmlChar libeetNodeText[] = "Text";


const xmlChar libeetSoapFaultCodeVersionMismatch[] = "VersionMismatch";
const xmlChar libeetSoapFaultCodeMustUnderstand[] = "MustUnderstand";
const xmlChar libeetSoapFaultCodeClient[] = "Client";
const xmlChar libeetSoapFaultCodeServer[] = "Server";
const xmlChar libeetSoapFaultCodeReceiver[] = "Receiver";
const xmlChar libeetSoapFaultCodeSender[] = "Sender";
const xmlChar libeetSoapFaultDataEncodningUnknown[] = "DataEncodingUnknown";

#endif /* LIBEET_NO_SOAP */
