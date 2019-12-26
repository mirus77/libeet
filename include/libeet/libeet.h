
#ifndef __EETSigner_H__
#define __EETSigner_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define LIBXML_STATIC
#define LIBXSLT_STATIC
#define XMLSEC_STATIC
#define XMLSEC_CRYPTO_OPENSSL
#define XMLSEC_NO_CRYPTO_DYNAMIC_LOADING

#ifdef _DEBUG
#	ifndef DEBUG
#		define DEBUG
#	endif // !DEBUG
#endif // _DEBUG

#pragma comment(linker, "/STACK:2000000")
#pragma comment(linker, "/HEAP:2000000")

#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#include <libxslt/security.h>
#endif /* XMLSEC_NO_XSLT */

#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/crypto.h>
#include <xmlsec/templates.h>
#include <xmlsec/base64.h>
#include <xmlsec/app.h>

#include <libeet/version.h>
#include <libeet/exports.h>
#include <libeet/keysmngr.h>
#include <libeet/errors.h>
#include <libeet/strings.h>

	EET_EXPORT void * eetMalloc(size_t size);
	EET_EXPORT void * eetCalloc(size_t size);
	EET_EXPORT void eetFree(void *ptr);

	EET_EXPORT int eetSignerInit(void);
	EET_EXPORT void eetSignerCleanUp(void);
	EET_EXPORT void eetSignerShutdown(void);
	EET_EXPORT int eetSignerLoadPFXKeyFile(xmlSecKeysMngrPtr mngr, const xmlChar * FileName, const xmlChar * pwd);
	EET_EXPORT int eetSignerLoadPFXKeyMemory(xmlSecKeysMngrPtr mngr, const xmlSecByte * data, xmlSecSize dataSize, const xmlChar * pwd);
	EET_EXPORT int eetSignerAddTrustedCertFile(xmlSecKeysMngrPtr mngr, const xmlChar * FileName);
	EET_EXPORT int eetSignerAddTrustedCertMemory(xmlSecKeysMngrPtr mngr, const xmlSecByte * data, xmlSecSize dataSize);
	EET_EXPORT xmlChar * eetSignerSignString(xmlSecKeysMngrPtr mngr, xmlChar * Data);
	EET_EXPORT xmlChar * eetSignerMakePKP(xmlSecKeysMngrPtr mngr, xmlChar * Data);
	EET_EXPORT xmlChar * eetSignerMakeBKP(xmlSecKeysMngrPtr mngr, xmlChar * Data);
	EET_EXPORT int eetSignerSignRequest(xmlSecKeysMngrPtr mngr, const xmlSecByte * data, xmlSecSize dataSize, xmlChar ** outbufp);
	EET_EXPORT int eetSignerVerifyResponse(xmlSecKeysMngrPtr mngr, const xmlSecByte * data, xmlSecSize dataSize);
	EET_EXPORT xmlChar * eetSignerGetRawCertDataAsBase64String(xmlSecKeysMngrPtr mngr);

	EET_EXPORT xmlChar * eetSignerlibeetVersion(void);
	EET_EXPORT xmlChar * eetSignerlibXmlVersion(void);
	EET_EXPORT xmlChar * eetSignerxmlSecVersion(void);
	EET_EXPORT xmlChar * eetSignerCryptoVersion(void);

	EET_EXPORT __time64_t *eetSignerUTCToLocalTime(__time64_t *UTC_time);

	void SetDefaultKeysMngr(xmlSecKeysMngrPtr mngr);
	xmlSecKeysMngrPtr GetDefaultKeysMngr(void);
	xmlSecKeysMngrPtr getKeysMngr(xmlSecKeysMngrPtr mngr);

	void eetSignerAddBSTCert(xmlSecKeysMngrPtr mngr, const xmlChar * data);
	void eetSignerRemoveBSTCert(xmlSecKeysMngrPtr mngr);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __EETSigner_H__ */