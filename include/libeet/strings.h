#ifndef __EETSignerStrings_H__
#define __EETSignerStrings_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>

/***************************
 *
 * Global Namespaces 
 * 
 ****************************/
const xmlChar libeetWsseNs[];
const xmlChar libeetWsuNs[];
const xmlChar libeetExcNs[];
const xmlChar libeetWsseNsPrefix[];
const xmlChar libeetWsuNsPrefix[];
const xmlChar libeetSoap11Ns[];
const xmlChar libeetSoap12Ns[];


/***************************
 *
 * Wsse Nodes
 *
 ****************************/

const xmlChar libeetNodeSecurity[];
const xmlChar libeetNodeBinarySecurityToken[];
const xmlChar libeetNodeSecurityTokenReference[];
const xmlChar libeetNodeSecurityAttrValueType[];
const xmlChar libeetNodeSecurityAttrValueTypeValue[];
const xmlChar libeetNodeWsuAttrIdName[];
const xmlChar libeetNodeSecurityAttrEncodingType[];
const xmlChar libeetNodeSecurityAttrEncodingTypeValue[];

/***************************
 *
 * Other
 *
 ****************************/
const xmlChar libeetSchema[];
const xmlChar libeetSoapEnvelopePrefix[];
const xmlChar libeetSoapHeaderPrefix[];

#ifndef LIBEET_NO_SOAP
/*************************************************************************
 *
 * SOAP 1.1/1.2 strings
 *
 ************************************************************************/
const xmlChar libeetNodeEnvelope[];
const xmlChar libeetNodeHeader[];
const xmlChar libeetNodeBody[];
const xmlChar libeetNodeFault[];
const xmlChar libeetNodeFaultCode[];
const xmlChar libeetNodeFaultString[];
const xmlChar libeetNodeFaultActor[];
const xmlChar libeetNodeFaultDetail[];
const xmlChar libeetNodeCode[];
const xmlChar libeetNodeReason[];
const xmlChar libeetNodeNode[];
const xmlChar libeetNodeRole[];
const xmlChar libeetNodeDetail[];
const xmlChar libeetNodeValue[];
const xmlChar libeetNodeSubcode[];
const xmlChar libeetNodeText[];

const xmlChar libeetSoapFaultCodeVersionMismatch[];
const xmlChar libeetSoapFaultCodeMustUnderstand[];
const xmlChar libeetSoapFaultCodeClient[];
const xmlChar libeetSoapFaultCodeServer[];
const xmlChar libeetSoapFaultCodeReceiver[];
const xmlChar libeetSoapFaultCodeSender[];
const xmlChar libeetSoapFaultDataEncodningUnknown[];
#endif /* LIBEET_NO_SOAP */


static const xmlChar * PFXCERT_KEYNAME = BAD_CAST("p");
static const xmlChar * RESPONSECERT_KEYNAME = BAD_CAST("responsecert");

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __EETSignerStrings_H__ */