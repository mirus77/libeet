
#ifndef __EETSigner_ERRORS_H__
#define __EETSigner_ERRORS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <libeet/libeet.h>

	/*******************************************************************
	*
	* Error functions
	*
	*******************************************************************/
	/**
	* libeetErrorsCallback:
	* @file:               the error location file name (__FILE__ macro).
	* @line:               the error location line number (__LINE__ macro).
	* @func:               the error location function name (__func__ macro).
	* @errorObject:        the error specific error object
	* @errorSubject:       the error specific error subject.
	* @reason:             the error code.
	* @msg:                the additional error message.
	*
	* The errors reporting callback function.
	*/
	typedef void(*libeetErrorsCallback)     (const char* file,
		int line,
		const char* func,
		const char* errorObject,
		const char* errorSubject,
		int reason,
		const char* msg);

	EET_EXPORT void              libeetErrorsSetCallback(libeetErrorsCallback callback);
	EET_EXPORT void              libeetErrorsDefaultCallback(const char* file,
		int line,
		const char* func,
		const char* errorObject,
		const char* errorSubject,
		int reason,
		const char* msg);
	EET_EXPORT void              libeetErrorsDefaultCallbackEnableOutput(int enabled);

	EET_EXPORT int               libeetErrorsGetCode(xmlSecSize pos);
	EET_EXPORT const char*       libeetErrorsGetMsg(xmlSecSize pos);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __EETSigner_ERRORS_H__ */