
#include "stdafx.h"

#include "globals.h"

#include <stdlib.h>
#include <stdint.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/base64.h>

#include <libeet/encodeutils.h>


#define handleErrors abort

xmlChar *
eetSignerSHA1(xmlSecByte *buf, xmlSecSize buflen)
{
	EVP_MD_CTX *ctx;
	int res = 0;

	if ((ctx = EVP_MD_CTX_create()) == NULL)
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

	if (1 != EVP_DigestFinal_ex(ctx, digest, &digest_len))
	{
		res = -3;
		handleErrors();
	}
	digest[ctx->digest->md_size] = '\0';
	EVP_MD_CTX_destroy(ctx);

	return(xmlStrdup((xmlChar *) digest));
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