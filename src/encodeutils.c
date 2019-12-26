
#include "stdafx.h"

#include "globals.h"

#include <stdlib.h>
#include <stdint.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>
#include <xmlsec/base64.h>

#include <libeet/encodeutils.h>


#define handleErrors abort

int
eetSignerSHA1(xmlSecByte *buf, xmlSecSize buflen, xmlSecByte ** outbuf, xmlSecSize * outlen)
{
	xmlSecAssert2(outbuf != NULL, -1);
	xmlSecAssert2(outlen != NULL, -1);

	EVP_MD_CTX *ctx = NULL;
	int res = 0;
	
	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
		handleErrors();

	if (1 != EVP_DigestInit_ex(ctx, EVP_sha1(), NULL))
	{
		res = -1;
		handleErrors();
	}


	if (1 != EVP_DigestUpdate(ctx, buf, buflen))
	{
		res = -2;
		handleErrors();
	}

	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_len = sizeof(digest);
	unsigned int md_size = 0;

	if (1 != EVP_DigestFinal_ex(ctx, digest, &digest_len))
	{
		res = -3;
		handleErrors();
	}

	(*outlen) = digest_len;
	(*outbuf) = xmlStrndup((xmlChar *)digest, digest_len);

	EVP_MD_CTX_free(ctx);

	return(res);
}

int
eetSignerBase64Encode(xmlSecByte *buf, xmlSecSize buflen, xmlSecByte ** outbufp)
{
	*outbufp = xmlSecBase64Encode(buf, buflen, 0);
	return (1);
}


int
eetSignerBase16Encode(xmlSecByte *inbuf, xmlSecSize buflen, xmlSecByte * outbuf)
{
	xmlSecSize i;
	static const char hextable[20] = "0123456789ABCDEF";

	if (!inbuf) return -1;

	if (!outbuf) return -2;

	unsigned char ch = '\0';
	for (i = 0; i < buflen; i++) {
		ch = inbuf[i];
		outbuf[i * 2] = hextable[(ch >> 4) & 0x0f];
		outbuf[i * 2 + 1] = hextable[ch & 0xf];
	}
	
	return (1);
}