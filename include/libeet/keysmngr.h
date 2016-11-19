#ifndef __EETSigner_KeysMngr_H__
#define __EETSigner_KeysMngr_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <libeet/libeet.h>

#include <xmlsec/xmlsec.h>

#include <openssl/x509.h>


	typedef struct x509_st libeetX509, *libeetX509Ptr;

	EET_EXPORT xmlSecKeysMngrPtr eetSignerKeysMngrCreate(void);
	EET_EXPORT void eetSignerKeysMngrDestroy(xmlSecKeysMngrPtr mngr);
	EET_EXPORT void eetSignerSetDefaultKeysMngr(xmlSecKeysMngrPtr mngr);

	EET_EXPORT libeetX509Ptr eetSignerGetX509KeyCert(xmlSecKeysMngrPtr mngr);

	EET_EXPORT int eetSignerX509GetSubject(libeetX509Ptr X509Cert, xmlChar ** Subject);
	EET_EXPORT int eetSignerX509GetSerialNum(libeetX509Ptr X509Cert, xmlChar ** SerialNum);
	EET_EXPORT int eetSignerX509GetValidDate(libeetX509Ptr X509Cert, time_t * notBefore, time_t * notAfter);
	EET_EXPORT int eetSignerX509GetIssuerName(libeetX509Ptr X509Cert, xmlChar ** IssuerName);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __EETSigner_KeysMngr_H__ */