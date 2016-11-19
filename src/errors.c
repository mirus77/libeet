#include "globals.h"

#include <libeet/libeet.h>
#include <libeet/errors.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/errors.h>

void
libeetErrorsSetCallback(libeetErrorsCallback callback)
{
	xmlSecErrorsSetCallback(callback);
}

void              
libeetErrorsDefaultCallback(const char* file,
int line,
const char* func,
const char* errorObject,
const char* errorSubject,
int reason,
const char* msg)
{
	xmlSecErrorsDefaultCallback(
		file,
		line,
		func,
		errorObject,
		errorSubject,
		reason,
		msg
		);

}

void
libeetErrorsDefaultCallbackEnableOutput(int enabled)
{
	xmlSecErrorsDefaultCallbackEnableOutput(enabled);
}

int
libeetErrorsGetCode(xmlSecSize pos)
{
	return(xmlSecErrorsGetCode(pos));
}

const char*       
libeetErrorsGetMsg(xmlSecSize pos)
{
	return(xmlSecErrorsGetMsg(pos));
}