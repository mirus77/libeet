#ifndef __EETSignerTemplates_H__
#define __EETSignerTemplates_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
	
#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>

	xmlNodePtr eetSignerTmplSecurityCreate(xmlNodePtr parentNode, const xmlChar *id, const xmlChar *bstValue, const xmlChar *idBody);
	xmlNodePtr eetSignerTmplEnvelopeCreate(xmlDocPtr doc, const xmlChar *nsPrefix, const xmlChar *idBody);
	xmlNodePtr eetSignerTmplSecurityCreateNsPref(xmlNodePtr parentNode, const xmlChar *id, const xmlChar *nsPrefix, const xmlChar *bstValue, const xmlChar *idBody);
	xmlNodePtr eetSignerTmplBinarySecurityTokenCreate(xmlNodePtr securityNode, const xmlChar *id, const xmlChar *Value, const xmlChar *idBody);
	xmlNodePtr eetSignerTmplSignatureCreate(xmlNodePtr securityNode, const xmlChar *id, const xmlChar *idBody);
	xmlNodePtr eetSignerTmplSignatureCreateNsPref(xmlNodePtr parentNode, const xmlChar *id, const xmlChar *nsPrefix, const xmlChar *idBody);
	xmlNodePtr eetSignerTmplSignatureKeyInfoCreate(xmlNodePtr signNode, const xmlChar *id);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __EETSignerTemplates_H__ */