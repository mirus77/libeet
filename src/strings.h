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

static const xmlChar * PFXCERT_KEYNAME = BAD_CAST("p");

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __EETSignerStrings_H__ */