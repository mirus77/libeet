
#ifndef __EETSigner_EXPORTS_H__
#define __EETSigner_EXPORTS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#if !defined EET_EXPORT
#  if defined(_WIN32)	
# 	if defined(IN_LIBEET)
#      if !defined(LIBEET_STATIC)
#        define EET_EXPORT __declspec(dllexport)
#      else
#        define EET_EXPORT extern
#      endif
#	else
#     if 1
#       define EET_EXPORT
#     else
#       if !defined(LIBEET_STATIC)
#         define EET_EXPORT __declspec(dllimport)
#       else
#         define EET_EXPORT
#       endif
#     endif
#   endif
#  else
#    define EET_EXPORT
#  endif
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __EETSigner_EXPORTS_H__ */