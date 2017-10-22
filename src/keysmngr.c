
#include "globals.h"

#include <libeet/libeet.h>
#include <libeet/encodeutils.h>
#include <libeet/keysmngr.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>

#include <memory.h>
#include "strings.h"

xmlSecKeysMngrPtr
eetSignerKeysMngrCreate(void)
{
	xmlSecKeysMngrPtr mngr = xmlSecKeysMngrCreate();
	int resini = xmlSecCryptoAppDefaultKeysMngrInit(mngr);
#if defined(DEBUG)
	if (NULL != mngr)
	{
		fprintf(stdout, "eetSignerKeysMngrCreated : %s\n", "OK");
	}
	else
	{
		fprintf(stdout, "eetSignerKeysMngrCreated : %s\n", "failed");
	}
	if (resini < 0)
	{
		fprintf(stdout, "eetSignerKeysMngrInitialized : %s\n", "failed");
	}
	else
	{
		fprintf(stdout, "eetSignerKeysMngrInitialized : %s\n", "OK");
	}
#endif
	return(mngr);
}

void 
eetSignerKeysMngrDestroy(xmlSecKeysMngrPtr mngr)
{
	xmlSecKeysMngrDestroy(mngr);
#if defined(DEBUG)
	fprintf(stdout, "eetSignerKeysMngrDestroyed\n");
#endif
}

void 
eetSignerSetDefaultKeysMngr(xmlSecKeysMngrPtr mngr)
{
	SetDefaultKeysMngr(mngr);
	int resini = xmlSecCryptoAppDefaultKeysMngrInit(mngr);
#if defined(DEBUG)
	if (NULL != GetDefaultKeysMngr())
	{
		fprintf(stdout, "eetSignerDefaultKeysMngrCreated : %s\n", "OK");
	}
	else
	{
		fprintf(stdout, "eetSignerDefaultKeysMngrCreated : %s\n", "failed");
	}
	if (resini < 0)
	{
		fprintf(stdout, "eetSignerDefaultKeysMngrInitialized : %s\n", "failed");
	}
	else
	{
		fprintf(stdout, "eetSignerDefaultKeysMngrInitialized : %s\n", "OK");
	}
#endif
}

libeetX509Ptr 
eetSignerGetX509KeyCert(xmlSecKeysMngrPtr mngr)
{
	libeetX509Ptr X509Tmp = NULL;
	libeetX509Ptr X509Cert = NULL;
	xmlSecKeyInfoCtxPtr keyInfoCtx = NULL;
    xmlSecKeyPtr secKey = NULL;
	xmlSecKeyDataPtr dataItem = NULL;


	xmlSecKeysMngrPtr _mngr = getKeysMngr(mngr);

	xmlSecAssert2(_mngr!= NULL, NULL);

    keyInfoCtx = xmlSecKeyInfoCtxCreate(_mngr);
	if (NULL == keyInfoCtx){
		xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"eetSignerGetX509KeyCert",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"Create keyInfoCtx failed!");
		goto godone;
	}

	secKey = xmlSecKeysMngrFindKey(_mngr, PFXCERT_KEYNAME, keyInfoCtx);
	if (NULL == secKey){
		xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"eetSignerGetX509KeyCert",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"Cannot find privkey!");
		fprintf(stdout, "eetSignerGetX509KeyCert : %s\n", "Cannot find privkey!");
		goto godone;
	}

	int iCount = xmlSecPtrListGetSize(secKey->dataList);
	for (int i = 0; i < iCount; i++)
	{
		xmlSecKeyDataPtr dataItem = xmlSecPtrListGetItem(secKey->dataList, i);
		if (xmlSecKeyDataIsValid(dataItem))
		{
			if (xmlSecKeyDataCheckId(dataItem, xmlSecOpenSSLKeyDataX509Id))
			{
				X509Tmp = xmlSecOpenSSLKeyDataX509GetKeyCert(dataItem);
				X509Cert = X509_dup(X509Tmp);
				goto godone;
			}
		}
	}

godone:
	if (NULL != keyInfoCtx)
		xmlSecKeyInfoCtxDestroy(keyInfoCtx);
	if (NULL != secKey)
		xmlSecKeyDestroy(secKey);

	return (X509Cert);
}

libeetX509Ptr 
eetSignerGetX509ResponseCert(xmlSecKeysMngrPtr mngr)
{
	libeetX509Ptr X509Tmp = NULL;
	libeetX509Ptr X509Cert = NULL;
	xmlSecKeyInfoCtxPtr keyInfoCtx = NULL;
	xmlSecKeyPtr secKey = NULL;
	xmlSecKeyDataPtr dataItem = NULL;


	xmlSecKeysMngrPtr _mngr = getKeysMngr(mngr);

	xmlSecAssert2(_mngr != NULL, NULL);

	keyInfoCtx = xmlSecKeyInfoCtxCreate(_mngr);
	if (NULL == keyInfoCtx){
		xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"eetSignerGetX509KeyCert",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"Create keyInfoCtx failed!");
		goto godone;
	}

	secKey = xmlSecKeysMngrFindKey(_mngr, RESPONSECERT_KEYNAME, keyInfoCtx);
	if (NULL == secKey){
		xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"eetSignerGetX509ResponseCert",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			"Cannot find privkey!");
		fprintf(stdout, "eetSignerGetX509ResponseCert : %s\n", "Cannot find resonse cert!");
		goto godone;
	}

	int iCount = xmlSecPtrListGetSize(secKey->dataList);
	for (int i = 0; i < iCount; i++)
	{
		xmlSecKeyDataPtr dataItem = xmlSecPtrListGetItem(secKey->dataList, i);
		if (xmlSecKeyDataIsValid(dataItem))
		{
			if (xmlSecKeyDataCheckId(dataItem, xmlSecOpenSSLKeyDataX509Id))
			{
				X509Tmp = xmlSecOpenSSLKeyDataX509GetCert(dataItem, i);
				X509Cert = X509_dup(X509Tmp);
				goto godone;
			}
		}
	}

godone:
	if (NULL != keyInfoCtx)
		xmlSecKeyInfoCtxDestroy(keyInfoCtx);
	if (NULL != secKey)
		xmlSecKeyDestroy(secKey);

	return (X509Cert);
}

#ifdef HAVE_TIMEGM
extern time_t timegm(struct tm *tm);
#else  /* HAVE_TIMEGM */
#ifdef WIN32
#define timegm(tm)      (mktime(tm) - _timezone)
#else /* WIN32 */
/* Absolutely not the best way but it's the only ANSI compatible way I know.
* If you system has a native struct tm --> GMT time_t conversion function
* (like timegm) use it instead.
*/
static time_t
my_timegm(struct tm *t) {
	time_t tl, tb;
	struct tm *tg;

	tl = mktime(t);
	if (tl == -1) {
		t->tm_hour--;
		tl = mktime(t);
		if (tl == -1) {
			return -1;
		}
		tl += 3600;
	}
	tg = gmtime(&tl);
	tg->tm_isdst = 0;
	tb = mktime(tg);
	if (tb == -1) {
		tg->tm_hour--;
		tb = mktime(tg);
		if (tb == -1) {
			return -1;
		}
		tb += 3600;
	}
	return (tl - (tb - tl));
}

#define timegm(tm) my_timegm(tm)
#endif /* WIN32 */
#endif /* HAVE_TIMEGM */

static int
X509CertGetTime(ASN1_TIME* t, time_t* res) {
	struct tm tm;
	int offset;

	xmlSecAssert2(t != NULL, -1);
	xmlSecAssert2(res != NULL, -1);

	(*res) = 0;
	if (!ASN1_TIME_check(t)) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			NULL,
			"ASN1_TIME_check",
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
		return(-1);
	}

	memset(&tm, 0, sizeof(tm));

#define g2(p) (((p)[0]-'0')*10+(p)[1]-'0')
	if (t->type == V_ASN1_UTCTIME) {
		xmlSecAssert2(t->length > 12, -1);


		/* this code is copied from OpenSSL asn1/a_utctm.c file */
		tm.tm_year = g2(t->data);
		if (tm.tm_year < 50) {
			tm.tm_year += 100;
		}
		tm.tm_mon = g2(t->data + 2) - 1;
		tm.tm_mday = g2(t->data + 4);
		tm.tm_hour = g2(t->data + 6);
		tm.tm_min = g2(t->data + 8);
		tm.tm_sec = g2(t->data + 10);
		if (t->data[12] == 'Z') {
			offset = 0;
		}
		else {
			xmlSecAssert2(t->length > 16, -1);

			offset = g2(t->data + 13) * 60 + g2(t->data + 15);
			if (t->data[12] == '-') {
				offset = -offset;
			}
		}
		tm.tm_isdst = -1;
	}
	else {
		xmlSecAssert2(t->length > 14, -1);

		tm.tm_year = g2(t->data) * 100 + g2(t->data + 2);
		tm.tm_mon = g2(t->data + 4) - 1;
		tm.tm_mday = g2(t->data + 6);
		tm.tm_hour = g2(t->data + 8);
		tm.tm_min = g2(t->data + 10);
		tm.tm_sec = g2(t->data + 12);
		if (t->data[14] == 'Z') {
			offset = 0;
		}
		else {
			xmlSecAssert2(t->length > 18, -1);

			offset = g2(t->data + 15) * 60 + g2(t->data + 17);
			if (t->data[14] == '-') {
				offset = -offset;
			}
		}
		tm.tm_isdst = -1;
	}
#undef g2
	(*res) = timegm(&tm) - offset * 60;
	return(0);
}

int 
eetSignerX509GetSubject(libeetX509Ptr X509Cert, xmlChar ** Subject)
{
	xmlSecAssert2(X509Cert != NULL, -1);
	xmlSecAssert2(Subject != NULL, -1);
	char buf[1024];
	char * tmp = X509_NAME_oneline(X509_get_subject_name(X509Cert), buf, sizeof(buf));
	(*Subject) = xmlStrdup(tmp);
	return(0);
}

int 
eetSignerX509GetSerialNum(libeetX509Ptr X509Cert, xmlChar ** SerialNum)
{
	xmlSecAssert2(X509Cert != NULL, -1);
	xmlSecAssert2(SerialNum != NULL, -1);

	BIGNUM *bn = NULL;
	bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(X509Cert), NULL);
	if (bn != NULL) {
		(*SerialNum) = xmlStrdup(BN_bn2hex(bn));
		BN_free(bn);
	}
	else {
		(*SerialNum) = xmlStrdup((xmlChar *) "unknown");
	}
	return(0);
}

int 
eetSignerX509GetValidDate(libeetX509Ptr X509Cert, time_t * notBefore, time_t * notAfter){

	(*notAfter) = 0;
	(*notBefore) = 0;

	if ((X509_get_notBefore(X509Cert) != NULL) && (X509_get_notAfter(X509Cert) != NULL))
	{
		if (X509CertGetTime(X509_get_notBefore(X509Cert), notBefore) < 0)
		{
			return(-1);
		}
		if (X509CertGetTime(X509_get_notAfter(X509Cert), notAfter) < 0)
		{
			return(-1);
		}
		return(0);
	}
	return(-1);
}

int
eetSignerX509GetIssuerName(libeetX509Ptr X509Cert, xmlChar ** IssuerName)
{
	xmlSecAssert2(X509Cert != NULL, -1);
	xmlSecAssert2(IssuerName != NULL, -1);

	char buf[1024];
	(*IssuerName) = xmlStrdup(X509_NAME_oneline(X509_get_issuer_name(X509Cert), buf, sizeof(buf)));

	return(0);
}