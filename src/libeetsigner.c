// libeetsigner.c : Defines the exported functions for the DLL application.
//

#include "globals.h"

#include <memory.h>
#include <string.h>

#include <libeet/libeet.h>
#include <libeet/encodeutils.h>
#include <libeet/soap.h>
#include "templates.h"

#include <openssl/x509.h>
#include <openssl/asn1.h>

#include <xmlsec/openssl/x509.h>
#include <xmlsec/app.h>
#include <xmlsec/errors.h>

static int eetSignerInitialized = 0;
static xmlSecKeysMngrPtr defaultkeysmngr = NULL;
const int SIGSIZE = 256;

#define xmlSecSimpleKeysStoreSize \
        (sizeof(xmlSecKeyStore) + sizeof(xmlSecPtrList))
#define xmlSecSimpleKeysStoreGetList(store) \
    ((xmlSecKeyStoreCheckSize((store), xmlSecSimpleKeysStoreSize)) ? \
        (xmlSecPtrListPtr)(((xmlSecByte*)(store)) + sizeof(xmlSecKeyStore)) : \
        (xmlSecPtrListPtr)NULL)

void *
eetMalloc(size_t size)
{
	return xmlMalloc(size);
}

void *
eetCalloc(size_t size)
{
	void * mem = xmlMalloc(size);
	memset(mem, 0, size);
	return (mem);
}

void
eetFree(void *ptr)
{
	xmlFree(ptr);
}

void
defaultKeysMngrCreate()
{
	if (NULL == defaultkeysmngr)
		SetDefaultKeysMngr(xmlSecKeysMngrCreate());
}

xmlSecKeysMngrPtr
getKeysMngr(xmlSecKeysMngrPtr mngr)
{
	if (NULL != mngr)
		return (mngr);
	return (defaultkeysmngr);
}

void
SetDefaultKeysMngr(xmlSecKeysMngrPtr mngr){
	if (NULL != defaultkeysmngr){
		xmlSecKeysMngrDestroy(defaultkeysmngr);
	}
	defaultkeysmngr = mngr;
	if (NULL != defaultkeysmngr){
		xmlSecCryptoAppDefaultKeysMngrInit(defaultkeysmngr);
	}
}

xmlSecKeysMngrPtr
GetDefaultKeysMngr(void)
{
	return(defaultkeysmngr);
}

int
eetSignerInit(void)
{
	int res = 0;

	if (eetSignerInitialized != 0)
		return 0;

	LIBXML_TEST_VERSION;

	xmlInitParser();
	xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
	xmlSubstituteEntitiesDefault(1);

	xmlKeepBlanksDefault(1); // pokud je 0 tak nefunguje VerifyXML

	xmlIndentTreeOutput = 0;  // nemaji se formatovat XML elementy

	xmlSecBase64SetDefaultLineSize(0); // Kvuli jednoradkove SignatureValue

	if (xmlSecInit() < 0)
	{
		xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"xmlSecInit",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
		res = -1;
	}
#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
	if (res == 0)
		if (xmlSecCryptoDLLoadLibrary("openssl") < 0) res = -2;
#endif /* XMLSEC_CRYPTO_DYNAMIC_LOADING */
	if (res == 0)
		if (xmlSecCheckVersionExt(1, 2, 18, xmlSecCheckVersionABICompatible) != 1)
		{
			xmlSecError(XMLSEC_ERRORS_HERE,
				NULL,
				"xmlSecCheckVersionExt",
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				XMLSEC_ERRORS_NO_MESSAGE);
			res = -3;
		}
	if (res == 0)
		if (xmlSecCryptoAppInit(NULL) < 0)
		{
			xmlSecError(XMLSEC_ERRORS_HERE,
				NULL,
				"xmlSecCryptoAppInit",
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				XMLSEC_ERRORS_NO_MESSAGE);
			res = -4;
		}
	if (res == 0)
		if (xmlSecCryptoInit() < 0)
		{
			xmlSecError(XMLSEC_ERRORS_HERE,
				NULL,
				"xmlSecCryptoInit",
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				XMLSEC_ERRORS_NO_MESSAGE);
			res = -5;
		}
	if (res == 0)
	{
		SetDefaultKeysMngr(NULL);
	    defaultkeysmngr = xmlSecKeysMngrCreate();
		if ((defaultkeysmngr == NULL) || (xmlSecCryptoAppDefaultKeysMngrInit(defaultkeysmngr) != 0))
		{
			xmlSecError(XMLSEC_ERRORS_HERE,
				NULL,
				"xmlSecCryptoAppDefaultKeysMngrInit",
				XMLSEC_ERRORS_R_XMLSEC_FAILED,
				XMLSEC_ERRORS_NO_MESSAGE);
			res = -6;
		}
	}
	if (res != 0)
	{
		if (res > -6) xmlSecCryptoShutdown();
		if (res > -5) xmlSecCryptoAppShutdown();
		if (res > -3) xmlSecShutdown();

#ifndef XMLSEC_NO_XSLT
		xsltCleanupGlobals();
#endif /* XMLSEC_NO_XSLT */

		xmlCleanupParser();

	}
	else {
		eetSignerInitialized = 1;
	}

	return (res);
}

void
eetSignerCleanUp(void)
{
	eetSignerShutdown();
	eetSignerInit();
}

void
eetSignerShutdown(void)
{
	if (eetSignerInitialized == 0)
		return;

	SetDefaultKeysMngr(NULL);
	xmlSecCryptoShutdown();
	xmlSecCryptoAppShutdown();
	xmlSecShutdown();

#ifndef XMLSEC_NO_XSLT
	xsltCleanupGlobals();
#endif /* XMLSEC_NO_XSLT */

	xmlCleanupParser();

	eetSignerInitialized = 0;
}

int
eetSignerLoadPFXKeyFile(xmlSecKeysMngrPtr mngr, const xmlChar * fileName, const xmlChar * pwd)
{
	int res = 0;
	xmlSecKeyPtr key = NULL;

	xmlSecAssert2(fileName != NULL, -1);
	xmlSecAssert2(pwd != NULL, -1);

	key = xmlSecCryptoAppKeyLoad((char *) fileName, xmlSecKeyDataFormatPkcs12, (char *) pwd, NULL, NULL);
	if (key != NULL)
	{
		if (xmlSecKeySetName(key, PFXCERT_KEYNAME) != 0) res = -2;
		if (res == 0)
			if (xmlSecCryptoAppDefaultKeysMngrAdoptKey(getKeysMngr(mngr), key) != 0) res = -3; else key = NULL;
	}
	else
	{
		res = -1;
	}

	return res;
}


int
eetSignerLoadPFXKeyMemory(xmlSecKeysMngrPtr mngr, const xmlSecByte * data, xmlSecSize dataSize, const xmlChar * pwd)
{
	int res = 0;
	xmlSecKeyPtr key = NULL;

	xmlSecAssert2(data != NULL, -1);
	xmlSecAssert2(dataSize > 0, -1);
	xmlSecAssert2(pwd != NULL, -1);

	key = xmlSecCryptoAppKeyLoadMemory(data, dataSize, xmlSecKeyDataFormatPkcs12, (char *) pwd, NULL, NULL);
	if (key != NULL)
	{
		if (xmlSecKeySetName(key, PFXCERT_KEYNAME) != 0) res = -2;
		if (res == 0)
			if (xmlSecCryptoAppDefaultKeysMngrAdoptKey(getKeysMngr(mngr), key) != 0)
			{
				res = -3;
			}
			else
			{
				key = NULL;
			}
	}
	else
	{
		res = -1;
	}

	return res;
}

int
eetSignerAddTrustedCertFile(xmlSecKeysMngrPtr mngr, const xmlChar * FileName)
{
	int res = 0;
	xmlSecKeyPtr key = NULL;
	xmlSecKeyDataFormat certkeyformat = xmlSecKeyDataFormatCertDer;

	xmlSecAssert2(FileName != NULL, -1);

	int len = xmlStrlen(FileName);

	if ((len > 4) && (strcmp(FileName + len - 4, ".pem") == 0)) {
		xmlSecKeyDataFormat certkeyformat = xmlSecKeyDataFormatCertPem;
	}

	if ((len > 4) && (strcmp(FileName + len - 4, ".der") == 0)) {
		xmlSecKeyDataFormat certkeyformat = xmlSecKeyDataFormatCertDer;
	}

	if ((len > 4) && (strcmp(FileName + len - 4, ".crt") == 0)) {
		xmlSecKeyDataFormat certkeyformat = xmlSecKeyDataFormatCertDer;
	}

	if ((len > 4) && (strcmp(FileName + len - 4, ".cer") == 0)) {
		xmlSecKeyDataFormat certkeyformat = xmlSecKeyDataFormatCertDer;
	}

	if (xmlSecCryptoAppKeysMngrCertLoad(getKeysMngr(mngr), (char *)FileName, certkeyformat, xmlSecKeyDataTypeTrusted) < 0)
	{
		res = -1;
	}
	return res;
}

int
eetSignerAddTrustedCertMemory(xmlSecKeysMngrPtr mngr, const xmlSecByte * data, xmlSecSize dataSize)
{
	int res = 0;
	xmlSecKeyPtr key = NULL;
    xmlSecKeyDataFormat certkeyformat = xmlSecKeyDataFormatCertDer;

	xmlSecAssert2(data != NULL, -1);
	xmlSecAssert2(dataSize > 0, -1);

	if (strstr(data, "-BEGIN CERTIFICATE-") != NULL)
	{
		certkeyformat = xmlSecKeyDataFormatCertPem;
	}

	if (xmlSecCryptoAppKeysMngrCertLoadMemory(getKeysMngr(mngr), data, dataSize, certkeyformat, xmlSecKeyDataTypeTrusted) < 0)
	{
		res = -1;
	}
	return res;
}


xmlChar *
eetSignerSignString(xmlSecKeysMngrPtr mngr, xmlChar * Data)
{
	xmlChar * res = NULL;

	xmlSecTransformCtxPtr TransCtx = NULL;
	xmlSecTransformPtr TransMethod = NULL;
	xmlChar * buf = NULL;
	int bufSz = 0;
	xmlSecKeyInfoCtxPtr keyInfoCtx = NULL;
	xmlSecKeyPtr secKey = NULL;

	TransCtx = xmlSecTransformCtxCreate();
	if (TransCtx == NULL) {
		fprintf(stderr, "Error: transform context creation failed.\n");
		goto godone;
	}

	buf = xmlStrdup(Data);
	bufSz = xmlStrlen(buf);

	if (xmlSecTransformCtxInitialize(TransCtx) != 0)
	{
		fprintf(stderr, "Error: transform context initialization failed.\n");
		goto godone;
	}

	keyInfoCtx = xmlSecKeyInfoCtxCreate(getKeysMngr(mngr));
	if (keyInfoCtx == NULL) {
		fprintf(stderr, "Error: keyInfo context creation failed.\n");
		goto godone;
	}

	secKey = xmlSecKeysMngrFindKey(getKeysMngr(mngr), PFXCERT_KEYNAME, keyInfoCtx);
	if (secKey == NULL)
	{
		fprintf(stderr, "Error: Find key failed.\n");
		goto godone;
	}

    TransMethod = xmlSecTransformCtxCreateAndAppend(TransCtx, xmlSecTransformRsaSha256Id);
	if (TransMethod == NULL) {
		fprintf(stderr, "Error: TransMethod creation failed.\n");
		goto godone;
	}

	TransMethod->operation = xmlSecTransformOperationSign;

	if (xmlSecTransformSetKey(TransMethod, secKey) != 0)
	{
		fprintf(stderr, "Error: Transform set Key failed.\n");
		goto godone;
	}

	if (xmlSecTransformCtxPrepare(TransCtx, 1) != 0)
	{
		fprintf(stderr, "Error: Transform Context prepare failed.\n");
		goto godone;
	}

	if (xmlSecTransformDefaultPushBin(TransCtx->first, buf, bufSz, 1, TransCtx) != 0)
	{
		fprintf(stderr, "Error: TransformDefaultPushBin failed.\n");
		goto godone;
	}

	if (TransCtx->result->size != SIGSIZE)
	{
		fprintf(stderr, "Error: Trans Context result size failed.\n");
		goto godone;
	}

	res = xmlStrndup(TransCtx->result->data, SIGSIZE);

godone:
	if (TransCtx != NULL)
		xmlSecTransformCtxDestroy(TransCtx);

	if (keyInfoCtx != NULL)
		xmlSecKeyInfoCtxDestroy(keyInfoCtx);

	if (secKey != NULL)
		xmlSecKeyDestroy(secKey);

	return (res);
}

xmlChar *
eetSignerMakePKP(xmlSecKeysMngrPtr mngr, xmlChar * Data)
{
	xmlChar * res = NULL;
	res = eetSignerSignString(mngr, Data);
	xmlChar ** res64p = eetMalloc(sizeof(xmlChar *));
	xmlChar * res64 = NULL;

	eetSignerBase64Encode(res, SIGSIZE, res64p);
	res64 = *res64p;
	if (res != NULL)
		eetFree(res);
	if (res64p != NULL)
		eetFree(res64p);
	return (res64);
}

xmlChar *
eetSignerMakeBKP(xmlSecKeysMngrPtr mngr, xmlChar * Data)
{
	int i,j;
#if defined(DEBUG)
	fprintf(stdout, "SignerMakeBPK input data : %s\n", Data);
#endif
	xmlChar * resout = NULL;
	xmlChar * encoded_text = NULL;
	xmlChar * s = eetSignerSignString(mngr, Data);

	xmlSecByte ** digest = eetMalloc(sizeof(digest));
	xmlSecSize digest_len = 0;
	if (eetSignerSHA1(s, SIGSIZE, digest, &digest_len) == 0)
	{
		encoded_text = (xmlChar *)eetCalloc((digest_len * 2) + 1);
		resout = (xmlChar *)eetCalloc((digest_len * 2) + 1 + 4);
		if (eetSignerBase16Encode(*digest, digest_len, encoded_text) != 1)
		{
#if defined(DEBUG)
			fprintf(stdout, "Base16Encode failed\n");
#endif
		}

		// normalize output for BKP
		j = 0;
		for (i = 0; i < xmlStrlen(encoded_text); i++)
		{
			if ((i == 8) || (i == 16) || (i == 24) || (i == 32))
			{
				resout[j] = '-';
				j++;
			}
			resout[j] = encoded_text[i];
			j++;
		}

		if (encoded_text != NULL)
		{
			eetFree(encoded_text);
		}

	};

	if (s != NULL)
	{
		eetFree(s);
	}

	if (*digest != NULL)
	{
		eetFree(*digest);
	}

	if (digest != NULL)
	{
		eetFree(digest);
	}

	return (resout);
}

int
normalizeRequestXML(xmlSecKeysMngrPtr mngr, const xmlDocPtr doc, const xmlChar * IdProp) {
	xmlNodePtr BSTNode = NULL;
	xmlNodePtr nodeEnvelope = NULL;
	xmlNodePtr nodeHeader = NULL;
	xmlNodePtr nodeBody = NULL;
	xmlNodePtr nodeBodyOld = NULL;
	xmlNodePtr nodeTrzba = NULL;
	xmlNodePtr SignatureNode = NULL;
	xmlNodePtr cur = NULL;
	xmlNodePtr nodeRoot = NULL;
	xmlNsPtr nsList = NULL;
	xmlNsPtr ns = NULL;

	xmlAttrPtr attr = NULL;
	xmlChar * attrName = NULL;

#if defined(DEBUG)
	FILE * fp;
#endif // DEBUG

	int res = -1;

	xmlSecAssert2(doc != NULL, -1);

	xmlSecAssert2(doc->children != NULL, -1);

	nodeRoot = xmlSecGetNextElementNode(doc->children);

	if ((nodeRoot != NULL) && !xmlSecCheckNodeName(nodeRoot, libeetNodeEnvelope, libeetSoap11Ns))
	{
		xmlUnlinkNode(nodeRoot);
		// create new Envelope
		nodeEnvelope = eetSignerTmplEnvelopeCreate(doc, libeetSoapEnvelopePrefix, BAD_CAST("id-TheBody"));
		if (NULL != nodeEnvelope){
			xmlDocSetRootElement(doc, nodeEnvelope);
			nodeHeader = libeetSoap11GetHeader(nodeEnvelope);
			nodeBody = libeetSoap11GetBody(nodeEnvelope);
			// old root element placed inside new body node
			xmlSecAddChildNode(nodeBody, nodeRoot);
		}
	}
	else
	{
		nodeEnvelope = nodeRoot;
		nodeHeader = libeetSoap11GetHeader(nodeEnvelope);
		nodeBodyOld = libeetSoap11GetBody(nodeEnvelope);
		if (nodeHeader != NULL)
		{
			xmlUnlinkNode(nodeHeader);
			xmlFreeNode(nodeHeader);
			xmlUnlinkNode(nodeBodyOld);
		}
		// create new Envelope
		nodeEnvelope = eetSignerTmplEnvelopeCreate(doc, libeetSoapEnvelopePrefix, BAD_CAST("id-TheBody"));
		if (NULL != nodeEnvelope){
			xmlDocSetRootElement(doc, nodeEnvelope);
			nodeHeader = libeetSoap11GetHeader(nodeEnvelope);
			nodeBody = libeetSoap11GetBody(nodeEnvelope);
			if (NULL != nodeBodyOld)
			{
				if (NULL != nodeBodyOld->children)
				{
					nodeTrzba = xmlSecGetNextElementNode(nodeBodyOld->children);
					if (NULL != nodeTrzba)
					{
						xmlSecAddChildNode(nodeBody, nodeTrzba);
					}
				}
			}
		}
	}

	/* register Body Id */
	if (NULL != nodeBody) {
		/* find pointer to id attribute */
		attr = xmlHasProp(nodeBody, IdProp);
		if (NULL == attr) {
			attr = xmlHasProp(nodeBody, xmlSecAttrId);
		}
		if (NULL != attr) {
			attrName = xmlNodeListGetString(doc, attr->children, 1);
			if (NULL != attrName){
				/*check that we don't have that id already registered */
				if (NULL == xmlGetID(doc, attrName))
				{
					xmlAddID(NULL, doc, attrName, attr);
				}
			}
		}
	}

	cur = xmlSecFindNode(nodeHeader, libeetNodeSecurity, libeetWsseNs);
	if (cur == NULL)
	{
		xmlChar * cert64 = eetSignerGetRawCertDataAsBase64String(mngr);
#if defined(DEBUG)
		fprintf(stdout, "Body Id : %s\r\n", attrName);
#endif // DEBUG
		if (NULL != eetSignerTmplSecurityCreate(nodeHeader, NULL, cert64, attrName))
		{

		}
		if (NULL != cert64)
			eetFree(cert64);
	}

	res = 0;

#if defined(DEBUG)
	errno_t err;
	err = fopen_s(&fp, "normalizedRequestXML.xml", "w");
	if (err == 0) {
		xmlDocDump(fp, doc);
		fclose(fp);
	}
#endif // DEBUG
	return (res);
}

int
eetSignerSignRequest(xmlSecKeysMngrPtr mngr, const xmlSecByte * data, xmlSecSize dataSize, xmlChar ** outbufp)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr node = NULL;
	xmlNodePtr nodeBody = NULL;
	xmlSecDSigCtxPtr dsigCtx = NULL;

#if defined(DEBUG)
	errno_t err;
	FILE * fp;
#endif // DEBUG

	int erCode = -1;
	int res = -1;
	xmlSecKeysMngrPtr _mngr = getKeysMngr(mngr);

	xmlSecAssert2(_mngr != NULL, -1);
	xmlSecAssert2(data != NULL, -1);
	xmlSecAssert2(outbufp != NULL, -1);

	/* load file */
	doc = xmlParseMemory((char *)data, dataSize);
	if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)) {
		fprintf(stderr, "Error: unable to parse document \n");
		goto done;
	}

#if defined(DEBUG)
	err = fopen_s(&fp, "signedRequestbefore.xml", "w");
	if (err == 0) {
		xmlDocDump(fp, doc);
		fclose(fp);
		fprintf(stdout, "Original input request into : %s\r\n", "signedRequestbefore.xml");
	}
#endif // DEBUG

	if (normalizeRequestXML(_mngr, doc, libeetNodeWsuAttrIdName) < 0) {
		fprintf(stderr, "Error: failed to normalize xml document\n");
		goto done;
	}

	/* find start node */
	node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
	if (node == NULL) {
		fprintf(stderr, "Error: start node not found in document\n");
		goto done;
	}

	/* find body node */
	nodeBody = xmlSecFindNode(xmlDocGetRootElement(doc), libeetNodeBody, libeetSoap11Ns);
	if (nodeBody == NULL) {
		fprintf(stderr, "Error: body node not found in document\n");
		goto done;
	}

	/* create signature context */
	dsigCtx = xmlSecDSigCtxCreate(_mngr);
	if (dsigCtx == NULL) {
		fprintf(stderr, "Error: failed to create signature context\n");
		goto done;
	}

	dsigCtx->keyInfoWriteCtx.base64LineSize = 0;

	if (xmlSecDSigCtxSign(dsigCtx, node) == 0)
	//if (1)
		{
#if defined(DEBUG)
			fprintf(stdout, "Signature verify is OK\r\n");
#endif // DEBUG
		res = 0;
		int * bufSz = eetMalloc(sizeof(bufSz));
		xmlDocDumpMemory(doc, outbufp, bufSz);
		if (bufSz != NULL) eetFree(bufSz);

#if defined(DEBUG)
		//xmlDocDump(stdout, doc);
		errno_t err;
		FILE * fp;
		err = fopen_s(&fp, "signedRequestafter.xml", "w");
		if (err == 0) {
			xmlDocDump(fp, doc);
			fclose(fp);
			fprintf(stdout, "Signed output saved into : %s\r\n", "signedRequestafter.xml");
		}
#endif // DEBUG
	}

done:
	/* cleanup */
	if (dsigCtx != NULL) {
		xmlSecDSigCtxDestroy(dsigCtx);
	}

	if (doc != NULL) {
		xmlFreeDoc(doc);
	}
	return(res);
}

int
normalizeResponseXML(const xmlDocPtr doc, const xmlChar * IdProp) {
	xmlNodePtr BSTNode = NULL;
	xmlNodePtr SignatureNode = NULL;
	xmlNodePtr Node = NULL;
	xmlNodePtr KeyInfoNode = NULL;
	xmlNodePtr x509Data = NULL;
	xmlNodePtr x509Certificate = NULL;
	xmlAttrPtr Attr;
	xmlChar * IdVal;

	int res = -1;

	xmlSecAssert2(doc != NULL, -1);

	if (xmlStrlen(libeetNodeBody) > 0) {
		Node = xmlSecFindNode(xmlDocGetRootElement(doc), libeetNodeBody, libeetSchema);
		if (NULL == Node)
			Node = xmlSecFindNode(xmlDocGetRootElement(doc), libeetNodeBody, libeetSoap11Ns);
		if (NULL != Node) {
			Attr = xmlHasProp(Node, IdProp);
			if (NULL != Attr) {
				IdVal = xmlGetProp(Node, IdProp);
				xmlAddID(NULL, doc, IdVal, Attr);
			}
		}
	}

	SignatureNode = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);

	if (NULL != SignatureNode) {
		BSTNode = xmlSecFindNode(xmlDocGetRootElement(doc), libeetNodeBinarySecurityToken, libeetWsseNs);
		if (NULL != BSTNode) {
			Attr = xmlHasProp(BSTNode, IdProp);
			if (NULL != Attr) {
				IdVal = xmlGetProp(BSTNode, IdProp);
				xmlAddID(NULL, doc, IdVal, Attr);
			}

			KeyInfoNode = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeKeyInfo, xmlSecDSigNs);
			if (NULL != KeyInfoNode) {
				xmlUnlinkNode(KeyInfoNode);
				xmlFreeNode(KeyInfoNode);
			}
			KeyInfoNode = xmlSecAddChild(SignatureNode, xmlSecNodeKeyInfo, xmlSecDSigNs);
			if (NULL == KeyInfoNode)
				return (-2);

			x509Data = xmlSecTmplKeyInfoAddX509Data(KeyInfoNode);
			if (NULL == x509Data)
				return (-3);

			x509Certificate = xmlSecTmplX509DataAddCertificate(x509Data);
			if (NULL == x509Certificate)
				return (-4);

			xmlNodeSetContent(x509Certificate, xmlNodeGetContent(BSTNode));
			xmlSecAddChildNode(x509Data, x509Certificate);
		}
		res = 0;
	}

#if defined(DEBUG)
	FILE * fp;
	errno_t err;
	err = fopen_s(&fp, "normalizedResponseXML.xml", "w");
	if (err == 0) {
		xmlDocDump(fp, doc);
		fclose(fp);
	}
#endif // DEBUG
	return (res);
}

int
eetSignerVerifyResponse(xmlSecKeysMngrPtr mngr, const xmlSecByte * data, xmlSecSize dataSize)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr node = NULL;
	xmlSecDSigCtxPtr dsigCtx = NULL;
	xmlNodePtr BSTNode = NULL;
	xmlNodePtr SignatureNode = NULL;
	int res = -1;

	xmlSecKeysMngrPtr _mngr = getKeysMngr(mngr);
	xmlSecAssert2(_mngr != NULL, -1);
	xmlSecAssert2(data != NULL, -1);

	eetSignerRemoveBSTCert(_mngr);

	/* load file */
	doc = xmlParseMemory((char *)data, dataSize);
	if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)) {
		fprintf(stderr, "Error: unable to parse document \n");
		goto done;
	}

	/* find start node */
	node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
	if (node == NULL) {
		fprintf(stderr, "Error: start node not found in document\n");
		goto done;
	}

	if (normalizeResponseXML(doc, BAD_CAST("Id")) < 0) {
		fprintf(stderr, "Error: failed to normalize xml document\n");
		goto done;
	}

	/* create signature context */
	dsigCtx = xmlSecDSigCtxCreate(_mngr);
	if (dsigCtx == NULL) {
		fprintf(stderr, "Error: failed to create signature context\n");
		goto done;
	}

	/* Verify signature */
	if (xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
		fprintf(stderr, "Error: signature verify\n");
		goto done;
	}

	/* print verification result to stdout */
	if (dsigCtx->status == xmlSecDSigStatusSucceeded) {
#if defined(DEBUG)
		fprintf(stdout, "Signature is OK\n");
#endif
		/* find BinarySecurityToken node */
		BSTNode = xmlSecFindNode(xmlDocGetRootElement(doc), libeetNodeBinarySecurityToken, libeetWsseNs);
		if (NULL != BSTNode) {
			eetSignerAddBSTCert(_mngr, xmlNodeGetContent(BSTNode));
		}
		res = dsigCtx->status;
	}
	else {
#if defined(DEBUG)
		fprintf(stdout, "Signature is INVALID\n");
#endif
		res = dsigCtx->status;
	}

done:
	/* cleanup */
	if (dsigCtx != NULL) {
		xmlSecDSigCtxDestroy(dsigCtx);
	}

	if (doc != NULL) {
		xmlFreeDoc(doc);
	}
	return(res);
}

xmlChar *
eetSignerGetRawCertDataAsBase64String(xmlSecKeysMngrPtr mngr)
{
	xmlSecKeyInfoCtxPtr keyInfoCtx = NULL;
    xmlSecKeyPtr secKey = NULL;
    xmlSecKeyDataPtr secKeyData = NULL;
	xmlChar *sCNSubject = NULL;
	xmlChar *res = NULL;
	X509 * x509cert = NULL;
	BIO * mem = NULL;
	xmlSecByte *p = NULL;
	int iSize = 0;
	int i;

	keyInfoCtx = xmlSecKeyInfoCtxCreate(getKeysMngr(mngr));
	if (keyInfoCtx == NULL)
	{
		fprintf(stdout, "Key Context creation failed !!!");
		goto godone;
	}

	secKey = xmlSecKeysMngrFindKey(getKeysMngr(mngr), PFXCERT_KEYNAME, keyInfoCtx);
	if (secKey == NULL)
	{
		fprintf(stdout, "Key not found !!!");
		goto godone;
	}

    secKeyData = xmlSecKeyGetData(secKey, xmlSecKeyDataX509Id);
	if (secKeyData == NULL)
	{
		fprintf(stdout, "KeyData not found !!!");
		goto godone;
	}

    iSize = xmlSecOpenSSLKeyDataX509GetCertsSize(secKeyData);

	for (i = 0; i < iSize; i++)
	{
		x509cert = xmlSecOpenSSLKeyDataX509GetCert(secKeyData, i);
		if (x509cert != NULL) {
			char *subjoneline = X509_NAME_oneline(X509_get_subject_name(x509cert), NULL, 0);
			//fprintf(stdout, "subjectneline : %i - %s\r\n", i, subjoneline);
			if (subjoneline != NULL)
			  OPENSSL_free(subjoneline);
			X509_NAME *subj = X509_get_subject_name(x509cert);
			int lastpos = -1;
			for (;;) {
				lastpos = X509_NAME_get_index_by_NID(subj, NID_commonName, lastpos);
				if (lastpos == -1)
					break;
				X509_NAME_ENTRY *e = X509_NAME_get_entry(subj, lastpos);				
				//if (xmlStrlen(e->value->data) > 0)
				if (e)
					{
					//fprintf(stdout, "subject : %i - %s\r\n", i, e->value->data);

					//extract public cert in base64
					p = NULL;
					mem = BIO_new(BIO_s_mem());
					if (mem != NULL) {
						i2d_X509_bio(mem, x509cert);
						BIO_flush(mem);
						int csize = BIO_get_mem_data(mem, &p);
						if ((csize > 0) && (p != NULL))
						{
							res = xmlSecBase64Encode(p, csize, 0);
						}
						BIO_free_all(mem);
					}
				}
			}
		}
	}
godone:
	if (keyInfoCtx != NULL)
		xmlSecKeyInfoCtxDestroy(keyInfoCtx);
	if (secKey != NULL)
		xmlSecKeyDestroy(secKey);

	return(res);
}

xmlChar *
eetSignerlibeetVersion(void)
{
	return BAD_CAST(LIBEET_VERSION);
}

xmlChar *
eetSignerlibXmlVersion(void)
{
	return BAD_CAST(LIBXML_DOTTED_VERSION);
}

xmlChar *
eetSignerxmlSecVersion(void)
{
	return BAD_CAST(XMLSEC_VERSION);
}
xmlChar *
eetSignerCryptoVersion(void)
{
	int bufSz = 500;
	char * buf = eetCalloc(bufSz);
	if (NULL != buf)
	{
	}
	if (SSLeay() == SSLEAY_VERSION_NUMBER) {
			sprintf_s(buf, bufSz, "%s", SSLeay_version(SSLEAY_VERSION));
	}
	else {
		sprintf_s(buf, bufSz, "%s (Library: %s)\n", OPENSSL_VERSION_TEXT, SSLeay_version(SSLEAY_VERSION));
	}
	return (buf);
}

__time64_t *
eetSignerUTCToLocalTime(__time64_t *UTC_time)
{
	errno_t err = 0;
	struct tm loctime;

	err = _localtime64_s(&loctime, UTC_time);
	if (err == 0)
	{
		time_t *res = eetMalloc(sizeof(time_t));
		if (NULL != res)
		{
			(*res) = mktime(&loctime);
			return(res);
		}
	}
	return(0);
}

void
eetSignerAddBSTCert(xmlSecKeysMngrPtr mngr, const xmlChar * data)
{
	xmlSecKeyInfoCtxPtr keyInfoCtx = NULL;
	xmlSecKeyPtr secKey = NULL;
	xmlSecKeyPtr secKeyNew = NULL;
	xmlSecKeyPtr tmpKey = NULL;

	xmlSecKeyStorePtr store = NULL;
    xmlSecPtrListPtr list = NULL;

	xmlSecSize size, pos;

	xmlChar * certheader = "-----BEGIN CERTIFICATE-----\n";
	xmlChar * certfooter = "\n-----END CERTIFICATE-----\n";

	size = xmlStrlen(certheader) + xmlStrlen(data) + xmlStrlen(certfooter);

	xmlChar * certstring = eetCalloc(size + 1);

	certstring = xmlStrcat(certstring, certheader);
	certstring = xmlStrcat(certstring, data);
	certstring = xmlStrcat(certstring, certfooter);

	keyInfoCtx = xmlSecKeyInfoCtxCreate(getKeysMngr(mngr));
	if (keyInfoCtx == NULL)
	{
		fprintf(stdout, "Key Context creation failed !!!");
		goto godone;
	}

	secKey = xmlSecKeysMngrFindKey(getKeysMngr(mngr), RESPONSECERT_KEYNAME, keyInfoCtx);

	secKeyNew = xmlSecCryptoAppKeyLoadMemory(certstring, xmlStrlen(certstring), xmlSecKeyDataFormatCertPem, NULL, NULL, NULL);
	if (secKeyNew == NULL)
	{
		fprintf(stdout, "BinarySecurityToken is not loaded !!!");
		goto godone;
	}

	if (xmlSecKeySetName(secKeyNew, RESPONSECERT_KEYNAME) != 0)
	{
		fprintf(stdout, "xmlSecKeySetName failed !!!");
		goto godone;
	}

	if (NULL != secKey)
	{
		store = xmlSecKeysMngrGetKeysStore(getKeysMngr(mngr));
		list = xmlSecSimpleKeysStoreGetList(store);
		size = xmlSecPtrListGetSize(list);
		for (pos = 0; pos < size; ++pos)
		{
			tmpKey = (xmlSecKeyPtr)xmlSecPtrListGetItem(list, pos);
			if ((NULL != tmpKey) && (xmlSecKeyMatch(tmpKey, RESPONSECERT_KEYNAME, &(keyInfoCtx->keyReq)) == 1))
			{
				if (xmlSecKeyCopy(tmpKey, secKeyNew) < 0)
				{
					fprintf(stdout, "xmlSecKeyCopy failed !!!");
					goto godone;
				}
				if (xmlSecKeySetName(tmpKey, RESPONSECERT_KEYNAME) != 0)
				{
					fprintf(stdout, "xmlSecKeySetName failed !!!");
					goto godone;
				}
			}

		}
	}
	else {
		if (xmlSecCryptoAppDefaultKeysMngrAdoptKey(getKeysMngr(mngr), secKeyNew) != 0)
		{
			fprintf(stdout, "xmlSecCryptoAppDefaultKeysMngrAdoptKey failed !!!");
			goto godone;
		}
	}


godone:
	if (certstring != NULL)
		eetFree(certstring);
	if (keyInfoCtx != NULL)
		xmlSecKeyInfoCtxDestroy(keyInfoCtx);
	if (secKey != NULL)
		xmlSecKeyDestroy(secKey);
}

void 
eetSignerRemoveBSTCert(xmlSecKeysMngrPtr mngr)
{
	xmlSecKeyInfoCtxPtr keyInfoCtx = NULL;
	xmlSecKeyPtr secKey = NULL;
	xmlSecKeyPtr secKeyNew = NULL;
	xmlSecKeyPtr tmpKey = NULL;

	xmlSecKeyStorePtr store = NULL;
	xmlSecPtrListPtr list = NULL;

	xmlSecSize size, pos;

	keyInfoCtx = xmlSecKeyInfoCtxCreate(getKeysMngr(mngr));
	if (keyInfoCtx == NULL)
	{
		fprintf(stdout, "Key Context creation failed !!!");
		goto godone;
	}

	secKey = xmlSecKeysMngrFindKey(getKeysMngr(mngr), RESPONSECERT_KEYNAME, keyInfoCtx);

	if (NULL != secKey)
	{
		store = xmlSecKeysMngrGetKeysStore(getKeysMngr(mngr));
		list = xmlSecSimpleKeysStoreGetList(store);
		size = xmlSecPtrListGetSize(list);
		for (pos = 0; pos < size; ++pos)
		{
			tmpKey = (xmlSecKeyPtr)xmlSecPtrListGetItem(list, pos);
			if ((NULL != tmpKey) && (xmlSecKeyMatch(tmpKey, RESPONSECERT_KEYNAME, &(keyInfoCtx->keyReq)) == 1))
			{
				if (xmlSecPtrListRemove(list, pos) < 0)
				{
					fprintf(stdout, "xmlSecPtrListRemove failed !!!");
					goto godone;
				}
			}
		}
	}

godone:
	if (keyInfoCtx != NULL)
		xmlSecKeyInfoCtxDestroy(keyInfoCtx);
	if (secKey != NULL)
		xmlSecKeyDestroy(secKey);
}