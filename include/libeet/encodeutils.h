
#ifndef __EETSignerEncodeUtils_H__
#define __EETSignerEncodeUtils_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <xmlsec/xmlsec.h>
#include <libeet/libeet.h>

	EET_EXPORT int eetSignerSHA1(xmlSecByte *buf, xmlSecSize buflen, xmlSecByte ** outbuf, xmlSecSize * outlen);
	EET_EXPORT int eetSignerBase64Encode(xmlSecByte *buf, xmlSecSize buflen, xmlSecByte ** outbufp);
	EET_EXPORT int eetSignerBase16Encode(xmlSecByte *inbuf, xmlSecSize buflen, xmlSecByte * outbuf);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __EETSignerEncode_H__ */