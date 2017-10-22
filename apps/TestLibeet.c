// TestLibeet.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include "libeet/libeet.h"
#include "libeet/encodeutils.h"

#include <stdio.h>
#include <stdlib.h>

int
loadkey(xmlSecKeysMngrPtr mngr)
{
	int res = -1;
	int fsize = 0;
	char *buf = NULL;
	errno_t err;
	FILE *f = NULL;

	/*
	if (eetSignerLoadPFXKeyFile(BAD_CAST("..\\data\\EET_CA1_Playground-CZ00000019.p12"), BAD_CAST("eet")) < 0)
	{
	fprintf(stdout, "Failed: Load PFX Key from memory");
	}
	*/

	fprintf(stdout, "Load: ..\\data\\EET_CA1_Playground-CZ00000019.p12");
	err = fopen_s(&f, "..\\data\\EET_CA1_Playground-CZ00000019.p12", "rb");
	if (err == 0)
	{
		fseek(f, 0, SEEK_END);
		fsize = ftell(f);
		fseek(f, 0, SEEK_SET);  //same as rewind(f);
		buf = (char *)eetMalloc(fsize);
		if (buf != NULL)
		{
			fread(buf, fsize, 1, f);
			if (eetSignerLoadPFXKeyMemory(mngr, BAD_CAST(buf), fsize, BAD_CAST("eet")) < 0)
			{
				fprintf(stdout, "Failed: Load PFX Key from memory");
				res = -2;
			}
			else
			{
				res = 0;
			}
			eetFree(buf);
		}
		fclose(f);
		fprintf(stdout, " - found");
	}
	else {
		fprintf(stdout, " - not found");
	}
	fprintf(stdout, "\n");
	return (res);
}

int 
loadtrustedcerts(xmlSecKeysMngrPtr mngr)
{
	int res = -1;
	int fsize = 0;
	char *buf = NULL;
	errno_t err;
	FILE *f = NULL;

	fprintf(stdout, "Load: ..\\data\\trusted_CA_pg.der");
	err = fopen_s(&f, "..\\data\\trusted_CA_pg.der", "rb");
	if (err == 0)
	{
		fseek(f, 0, SEEK_END);
		fsize = ftell(f);
		fseek(f, 0, SEEK_SET);  //same as rewind(f);
		buf = (char *)eetMalloc(fsize);
		if (buf != NULL)
		{
			fread(buf, fsize, 1, f);
			if (eetSignerAddTrustedCertMemory(mngr, BAD_CAST(buf), fsize) < 0)
			{
				fprintf(stdout, "Failed: Load Trusted cert from memory");
				res = -1;
			}
			else
			{
				res = 0;
			}
			eetFree(buf);
		}
		fclose(f);
		fprintf(stdout, " - found");
	}
	else
	{
		fprintf(stdout, " - not found");
	}
	fprintf(stdout, "\n");


	fprintf(stdout, "Load: ..\\data\\EET_CA1_Playground-ca.crt");
	if (eetSignerAddTrustedCertFile(mngr, BAD_CAST("..\\data\\EET_CA1_Playground-ca.crt")) < 0)
	{
		fprintf(stdout, "Failed: Load Trusted cert from memory");
		res = -1;
	}
	else
	{
		res = 0;
		fprintf(stdout, " - OK");
	}
	fprintf(stdout, "\n");

	return (res);
}

int
testVerifyResponse(xmlSecKeysMngrPtr mngr)
{
	int res = -1;
	int fsize = 0;
	char *buf = NULL;
	errno_t err;
	FILE *f = NULL;

	fprintf(stdout, "Load: ..\\data\\response.xml");
	err = fopen_s(&f, "..\\data\\response.xml", "rb");
	if (err == 0)
	{
		fprintf(stdout, " - found\n");
		fseek(f, 0, SEEK_END);
		fsize = ftell(f);
		fseek(f, 0, SEEK_SET);  //same as rewind(f);
		char *buf = (char *)eetMalloc(fsize + 1);
		if (buf != NULL)
		{
			fread(buf, fsize, 1, f);
			buf[fsize] = 0;
			if (eetSignerVerifyResponse(mngr, BAD_CAST(buf), fsize) == 1)
			{
				fprintf(stdout, "Signature Verify is OK\r\n");
				res = -2;
			}
			else
			{
				fprintf(stdout, "Signature Verify is failed\r\n");
				res = 0;
			}
			eetFree(buf);
		}
		fclose(f);
	}
	else
	{
		fprintf(stdout, " - not found\n");
	}
	return (res);
}

int
DoSignRequest(xmlSecKeysMngrPtr mngr)
{
	int res = -1;
	int fsize = 0;
	char *buf = NULL;
	errno_t err;
	FILE *f = NULL;

	//fprintf(stdout, "Load: ..\\data\\request.xml");
	//err = fopen_s(&f, "..\\data\\request.xml", "rb");
	//fprintf(stdout, "Load: ..\\data\\request_1.xml");
	//err = fopen_s(&f, "..\\data\\request_1.xml", "rb");
	//fprintf(stdout, "Load: ..\\data\\request_2.xml");
	//err = fopen_s(&f, "..\\data\\request_2.xml", "rb");
	fprintf(stdout, "Load: ..\\data\\request_3.xml");
	err = fopen_s(&f, "..\\data\\request_3.xml", "rb");
	if (err == 0)
	{
		fprintf(stdout, " - found\n");
		fseek(f, 0, SEEK_END);
		fsize = ftell(f);
		fseek(f, 0, SEEK_SET);  //same as rewind(f);
		xmlChar *buf = (xmlChar *)eetMalloc(fsize + 1);
		xmlChar **outbufp = eetMalloc(sizeof(outbufp));
		if (buf != NULL)
		{
			fread(buf, fsize, 1, f);
			buf[fsize] = 0;
			if (eetSignerSignRequest(mngr, BAD_CAST(buf), fsize, outbufp) < 0)
			{
				fprintf(stdout, "Signature make is failed\r\n");
				res = -2;
			}
			else 
			{
				fprintf(stdout, "Signature make is OK\r\n");
				res = 0;
			}
			eetFree(buf);
		}
		fclose(f);
	}
	else
	{
		fprintf(stdout, " - not found\n");
	}
	return (res);
}

int
DoSignString(xmlSecKeysMngrPtr mngr)
{
	char *res_s = NULL;

	res_s = (char *)eetSignerSignString(mngr, BAD_CAST("nejaky ten pekny text k podepsani"));
	if (res_s != NULL)
	{
		xmlChar ** res64p = eetMalloc(sizeof(xmlChar *));
		xmlChar * res64 = NULL;
		if (eetSignerBase64Encode(res_s, 256, res64p) == 1)
		{
			res64 = *res64p;
			if (res64p != NULL)
				eetFree(res64p);

			fprintf(stdout, "Signed string value: %s\r\n", res64);
		}
		eetFree(res_s);
		return (1);
	}
	else
	{
		return (1);
	}
}

int
DoMakeBKP(xmlSecKeysMngrPtr mngr)
{
	xmlChar *input = BAD_CAST("CZ27695450|273|/5546/RO24|461670|2016-11-24T18:50:39+01:00|37.00");
	xmlChar * res_s = eetSignerMakeBKP(mngr, input);
	if (res_s != NULL)
	{
		fprintf(stdout, "BKP string value: %s\r\n", res_s);
		eetFree(res_s);
		return (1);
	}
	return (1);
}

void
DoPrintSubject(libeetX509Ptr cert)
{
	xmlChar ** Subject = eetCalloc(sizeof(Subject));
	if (NULL != Subject){
		eetSignerX509GetSubject(cert, Subject);
		if (NULL != *Subject){
			fprintf(stdout, "Cert Subject : %s\n", *Subject);
			eetFree(*Subject);
		}
		eetFree(Subject);
	}
}

void
DoPrintSerialNumber(libeetX509Ptr cert)
{
	xmlChar ** SerialNum = eetCalloc(sizeof(SerialNum));
	if (NULL != SerialNum){
		eetSignerX509GetSerialNum(cert, SerialNum);
		if (NULL != *SerialNum){
			fprintf(stdout, "Cert Serial Number : %s\n", *SerialNum);
			eetFree(*SerialNum);
		}
		eetFree(SerialNum);
	}
}

void
DoPrintDates(libeetX509Ptr cert)
{
	time_t notBefore = 0;
	time_t notAfter = 0;

	char buffBefore[20];
	char buffAfter[20];
	struct tm _Tm;

	if (eetSignerX509GetValidDate(cert, &notBefore, &notAfter) == 0)
	{
		_localtime64_s(&_Tm, &notAfter);
		strftime(buffBefore, 20, "%Y-%m-%d %H:%M:%S", &_Tm);
		_localtime64_s(&_Tm, &notBefore);
		strftime(buffAfter, 20, "%Y-%m-%d %H:%M:%S", &_Tm);
		fprintf(stdout, "Cert valid After %s and before %s\n", buffAfter, buffBefore);
	}
}

void
DoPrintIssuer(libeetX509Ptr cert)
{
	xmlChar ** IssuerName = eetCalloc(sizeof(IssuerName));
	if (NULL != IssuerName){
		eetSignerX509GetIssuerName(cert, IssuerName);
		if (NULL != *IssuerName){
			fprintf(stdout, "Cert Issuer Name : %s\n", *IssuerName);
			eetFree(*IssuerName);
		}
		eetFree(IssuerName);
	}	
}

int main()
{
	char * res = NULL;
	int fsize = 0;
	char *buf = NULL;

	xmlSecKeysMngrPtr mngr = eetSignerKeysMngrCreate();

	fprintf(stdout, "libeet verze : %s\r\n", eetSignerlibeetVersion());
	fprintf(stdout, "libxml verze : %s\r\n", eetSignerlibXmlVersion());
	fprintf(stdout, "xmlsec verze : %s\r\n", eetSignerxmlSecVersion());
	fprintf(stdout, "crypto verze : %s\r\n", eetSignerCryptoVersion());
#ifdef LIBEET_STATIC
	fprintf(stdout, "libeet static : %s\r\n", "true");
#else
	fprintf(stdout, "libeet static : %s\r\n", "false");
#endif

	if (eetSignerInit() < 0) {
		fprintf(stdout, "eetSignetInit Failed\r\n");
		return -1;
	}

	fprintf(stdout, "== Load Keys ==\r\n");
	if (loadkey(mngr) == 0)
	{
		fprintf(stdout, "== Load Trusted certs ==\r\n");
		if (loadtrustedcerts(mngr) == 0)
		{
			fprintf(stdout, "== Sign string ==\r\n");
			DoSignString(mngr);
			fprintf(stdout, "== Make BPK ==\r\n");
			DoMakeBKP(mngr);
			fprintf(stdout, "== Sign Request == \r\n");
			DoSignRequest(mngr);
			fprintf(stdout, "== Verify Response ==\r\n");
			testVerifyResponse(mngr);
		}

		fprintf(stdout, "== Get X509 Key Cert ==\r\n");
		libeetX509Ptr x509Cert = eetSignerGetX509KeyCert(mngr);
		if (NULL != x509Cert){
			DoPrintSubject(x509Cert);
			DoPrintSerialNumber(x509Cert);
			DoPrintDates(x509Cert);
			DoPrintIssuer(x509Cert);
		}
		fprintf(stdout, "== Get X509 Key Cert ==\r\n");

		fprintf(stdout, "== Get X509 Response Cert ==\r\n");
		x509Cert = eetSignerGetX509ResponseCert(mngr);
		if (NULL != x509Cert){
			DoPrintSubject(x509Cert);
			DoPrintSerialNumber(x509Cert);
			DoPrintDates(x509Cert);
			DoPrintIssuer(x509Cert);
		}
		fprintf(stdout, "== Get X509 Response Cert ==\r\n");
	}


	if (NULL != mngr)
		eetSignerKeysMngrDestroy(mngr);

	eetSignerShutdown();
	printf("Press any key to continue.");
	getc(stdin);
	return 0;
}

