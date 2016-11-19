
#include "globals.h"

#include <libeet/libeet.h>
#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/soap.h>
#include <xmlsec/templates.h>
#include <xmlsec/transforms.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/strings.h>
#include <xmlsec/errors.h>

#include "strings.h"
#include "templates.h"


xmlNodePtr
eetSignerTmplSecurityCreate(xmlNodePtr parentNode, const xmlChar *id, const xmlChar *bstValue, const xmlChar *idBody)
{
	return(eetSignerTmplSecurityCreateNsPref(parentNode, id, libeetWsseNsPrefix, bstValue, idBody));
}

xmlNodePtr 
eetSignerTmplEnvelopeCreate(xmlDocPtr doc, const xmlChar *nsPrefix, const xmlChar *idBody)
{
	xmlNodePtr envNode = NULL;
	xmlNodePtr headerNode = NULL;
	xmlNodePtr bodyNode = NULL;
	xmlNsPtr ns = NULL;
	xmlAttrPtr attrId = NULL;

	xmlSecAssert2(doc != NULL, NULL);
	xmlSecAssert2(nsPrefix != NULL, NULL);

	envNode = xmlNewDocNode(doc, NULL, xmlSecNodeEnvelope, NULL);
	if (envNode != NULL){
		ns = xmlNewNs(envNode, xmlSecSoap11Ns, nsPrefix);
		if (NULL == ns){
			xmlFreeNode(envNode);
			return(NULL);
		}
		xmlSetNs(envNode, ns);

		headerNode = xmlSecAddChild(envNode, xmlSecNodeHeader, NULL);
		//ns = xmlNewNs(headerNode, xmlSecSoap11Ns, libeetSoapHeaderPrefix);
		//xmlSetNs(headerNode, ns);

		bodyNode = xmlSecAddChild(envNode, xmlSecNodeBody, xmlSecSoap11Ns);
		if (bodyNode != NULL){
			ns = xmlNewNs(bodyNode, libeetWsuNs, libeetWsuNsPrefix);
			if (NULL != idBody)
			{
				xmlSetProp(bodyNode, libeetNodeWsuAttrIdName, idBody);
			}
			else 
			{
				xmlSetProp(bodyNode, libeetNodeWsuAttrIdName, "id-TheBody");
			}
			if (NULL != attrId){
				xmlAddID(NULL, doc, libeetNodeWsuAttrIdName, attrId);
			}
		}
		else
		{
			xmlFreeNode(envNode);
			return(NULL);
		}
	}
	else {
		return(NULL);
	}

	return(envNode);
}

xmlNodePtr 
eetSignerTmplSecurityCreateNsPref(xmlNodePtr parentNode, const xmlChar *id, const xmlChar *nsPrefix, const xmlChar *bstValue, const xmlChar *idBody)
{
	xmlNodePtr secNode = NULL;
	xmlNodePtr btsNode = NULL;
	xmlNodePtr signNode = NULL;
	xmlNsPtr ns = NULL;
//	xmlAttrPtr attr = NULL;

	xmlSecAssert2(parentNode != NULL, NULL);
	xmlSecAssert2(nsPrefix != NULL, NULL);

	secNode = xmlSecAddChild(parentNode, libeetNodeSecurity, NULL);
	if (secNode != NULL){
		ns = xmlNewNs(secNode, libeetWsseNs, nsPrefix);
		xmlSetNs(secNode, ns);
		ns = xmlNewNs(secNode, libeetWsuNs, libeetWsuNsPrefix);
		xmlChar * attrValue = eetCalloc(100);
		if (NULL != attrValue)
		{
			if (sprintf_s((char *)attrValue, 100, "%s:mustUnderstand", libeetSoapEnvelopePrefix))
			{
				xmlSetProp(secNode, attrValue, BAD_CAST("1"));
			}
			eetFree(attrValue);
		}
		btsNode = eetSignerTmplBinarySecurityTokenCreate(secNode, libeetNodeBinarySecurityToken, bstValue, idBody);
		if (NULL == btsNode){
			xmlFreeNode(secNode);
			return (NULL);
		}
		signNode = eetSignerTmplSignatureCreate(secNode, id, idBody);
		if (NULL == btsNode){
			xmlFreeNode(secNode);
			return (NULL);
		}
	}


	return(secNode);
}

xmlNodePtr 
eetSignerTmplBinarySecurityTokenCreate(xmlNodePtr securityNode, const xmlChar *id, const xmlChar *Value, const xmlChar *idBody)
{
	xmlNodePtr btsNode = NULL;
	xmlNsPtr ns = NULL;
	xmlAttrPtr attr = NULL;

	btsNode = xmlSecAddChild(securityNode, libeetNodeBinarySecurityToken, NULL);
	attr = xmlNewProp(btsNode, libeetNodeSecurityAttrEncodingType, libeetNodeSecurityAttrEncodingTypeValue);
	if (NULL == attr){
		xmlFreeNode(btsNode);
		return (NULL);
	}
	attr = xmlNewProp(btsNode, libeetNodeSecurityAttrValueType, libeetNodeSecurityAttrValueTypeValue);
	if (NULL == attr){
		xmlFreeNode(btsNode);
		return (NULL);
	}
	if (NULL != id)
	{
		xmlSetProp(btsNode, libeetNodeWsuAttrIdName, "id-TheCert");
	}
	if (NULL != Value)
	{
		xmlNodeSetContent(btsNode, Value);
	}
	return(btsNode);
}

xmlNodePtr 
eetSignerTmplSignatureCreate(xmlNodePtr securityNode, const xmlChar *id, const xmlChar *idBody)
{
	return(eetSignerTmplSignatureCreateNsPref(securityNode, id, xmlSecDSigNs, idBody));
}

xmlNodePtr 
eetSignerTmplSignatureCreateNsPref(xmlNodePtr parentNode, const xmlChar *id, const xmlChar *nsPrefix, const xmlChar *idBody)
{
	xmlNodePtr signNode = NULL;
	xmlNodePtr signedInfoNode = NULL;
	xmlNodePtr transformsNode = NULL;
	xmlNodePtr referenceNode = NULL;
	xmlNodePtr cur;
	xmlNsPtr ns = NULL;
	xmlAttrPtr attr = NULL;

	signNode = xmlSecAddChild(parentNode, xmlSecNodeSignature, NULL);
	if (NULL == signNode)
	{
		return (NULL);
	}
	ns = xmlNewNs(signNode, xmlSecDSigNs, BAD_CAST("ds"));
	if (ns == NULL){
		xmlFreeNode(signNode);
		return (NULL);
	}
	xmlSetNs(signNode, ns);
	xmlSetProp(signNode, xmlSecAttrId, BAD_CAST("id-Signature"));

	signedInfoNode = xmlSecAddChild(signNode, xmlSecNodeSignedInfo, xmlSecDSigNs);
	if (NULL == signedInfoNode)
	{
		xmlFreeNode(signNode);
		return(NULL);
	}
	cur = xmlSecAddChild(signedInfoNode, xmlSecNodeCanonicalizationMethod, xmlSecDSigNs);
	if (NULL == cur)
	{
		xmlFreeNode(signNode);
		return(NULL);
	}
	if (xmlSetProp(cur, xmlSecAttrAlgorithm, xmlSecTransformExclC14NId->href) == NULL) {
		xmlFreeNode(signNode);
		return(NULL);
	}
	cur = xmlSecAddChild(cur, xmlSecNodeInclusiveNamespaces, NULL);
	if (NULL == cur)
	{
		xmlFreeNode(signNode);
		return(NULL);
	}
	ns = xmlNewNs(cur, xmlSecTransformExclC14NId->href, BAD_CAST("ec"));
	if (ns == NULL){
		xmlFreeNode(signNode);
		return (NULL);
	}
	xmlSetNs(cur, ns);
	xmlSetProp(cur, xmlSecAttrPrefixList, libeetSoapEnvelopePrefix);

	cur = xmlSecAddChild(signedInfoNode, xmlSecNodeSignatureMethod, xmlSecDSigNs);
	if (NULL == cur)
	{
		xmlFreeNode(signNode);
		return(NULL);
	}
	xmlSetProp(cur, xmlSecAttrAlgorithm, xmlSecHrefRsaSha256);

	referenceNode = xmlSecAddChild(signedInfoNode, xmlSecNodeReference, xmlSecDSigNs);
	if (NULL == referenceNode)
	{
		xmlFreeNode(signNode);
		return(NULL);
	}
	if (NULL != idBody){
		if (sizeof(idBody) < 498)
		{
			xmlChar * idBodyValue = eetCalloc(500);
			if (NULL != idBodyValue)
			{
				if (sprintf_s((char *)idBodyValue, 500, "#%s", idBody))
				{
					xmlSetProp(referenceNode, xmlSecAttrURI, idBodyValue);
				}
			}
		}
	}
	else {
		xmlSetProp(referenceNode, xmlSecAttrURI, BAD_CAST("#id-TheBody"));
	}

	// transforms
	transformsNode = xmlSecAddChild(referenceNode, xmlSecNodeTransforms, xmlSecDSigNs);
	if (NULL == transformsNode)
	{
		xmlFreeNode(signNode);
		return(NULL);
	}

	// transform
	cur = xmlSecAddChild(transformsNode, xmlSecNodeTransform, xmlSecDSigNs);
	if (NULL == cur)
	{
		xmlFreeNode(signNode);
		return(NULL);
	}
	if (xmlSetProp(cur, xmlSecAttrAlgorithm, xmlSecTransformExclC14NId->href) == NULL) {
		xmlFreeNode(signNode);
		return(NULL);
	}

	cur = xmlSecAddChild(cur, xmlSecNodeInclusiveNamespaces, NULL);
	if (NULL == cur)
	{
		xmlFreeNode(signNode);
		return(NULL);
	}
	ns = xmlNewNs(cur, xmlSecTransformExclC14NId->href, BAD_CAST("ec"));
	if (ns == NULL){
		xmlFreeNode(signNode);
		return (NULL);
	}
	xmlSetNs(cur, ns);
	xmlSetProp(cur, xmlSecAttrPrefixList, BAD_CAST(""));

	// DigestMethod
	cur = xmlSecAddChild(referenceNode, xmlSecNodeDigestMethod, xmlSecDSigNs);
	if (NULL == cur)
	{
		xmlFreeNode(signNode);
		return(NULL);
	}
	if (xmlSetProp(cur, xmlSecAttrAlgorithm, xmlSecHrefSha256) == NULL) {
		xmlFreeNode(signNode);
		return(NULL);
	}
	// DigestValue
	cur = xmlSecAddChild(referenceNode, xmlSecNodeDigestValue, xmlSecDSigNs);
	if (NULL == cur)
	{
		xmlFreeNode(signNode);
		return(NULL);
	}

	// Signature/SignatureValue
	cur = xmlSecAddChild(signNode, xmlSecNodeSignatureValue, xmlSecDSigNs);
	if (NULL == cur)
	{
		xmlFreeNode(signNode);
		return(NULL);
	}

	cur = eetSignerTmplSignatureKeyInfoCreate(signNode, BAD_CAST("TheKeyInfo"));
	if (NULL == cur)
	{
		xmlFreeNode(signNode);
		return(NULL);
	}

	return(signNode);
}

xmlNodePtr 
eetSignerTmplSignatureKeyInfoCreate(xmlNodePtr signNode, const xmlChar *id)
{
	xmlNodePtr keyInfoNode = NULL;
	xmlNodePtr cur= NULL;
	xmlNsPtr ns = NULL;

	// KeyInfo
	keyInfoNode = xmlSecAddChild(signNode, xmlSecNodeKeyInfo, xmlSecDSigNs);
	if (NULL == keyInfoNode)
	{
		xmlFreeNode(signNode);
		return(NULL);
	}
	if (NULL != id) {
		xmlSetProp(keyInfoNode, xmlSecAttrId, id);
	}

	// KeyInfo/SecurityTokenReference
	cur = xmlSecAddChild(keyInfoNode, libeetNodeSecurityTokenReference, NULL);
	if (NULL == cur)
	{
		xmlFreeNode(signNode);
		return(NULL);
	}
	ns = xmlNewNs(cur, libeetWsseNs, libeetWsseNsPrefix);
	if (ns == NULL){
		xmlFreeNode(signNode);
		return (NULL);
	}
	xmlSetNs(cur, ns);
	ns = xmlNewNs(cur, libeetWsuNs, libeetWsuNsPrefix);
	if (ns == NULL){
		xmlFreeNode(signNode);
		return (NULL);
	}
	xmlSetProp(cur, libeetNodeWsuAttrIdName, BAD_CAST("id-TheSecurityTokenReference"));

	// wsse:Reference
	cur = xmlSecAddChild(cur, xmlSecNodeReference, NULL);
	if (NULL == cur)
	{
		xmlFreeNode(signNode);
		return(NULL);
	}
	xmlSetProp(cur, xmlSecAttrURI, BAD_CAST("#id-TheCert"));
	xmlSetProp(cur, libeetNodeSecurityAttrValueType, libeetNodeSecurityAttrValueTypeValue);

	return(keyInfoNode);
}
