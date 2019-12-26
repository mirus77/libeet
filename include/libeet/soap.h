/*
 * a backup soap.h of deprecatation in xmlSec library !!!
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Simple SOAP messages parsing/creation.
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2017 Aleksey Sanin <aleksey@aleksey.com>
 */
#ifndef __XMLSEC_SOAP_H__
#define __XMLSEC_SOAP_H__

#ifndef LIBEET_NO_SOAP

#include <libxml/tree.h>
#include <libeet/libeet.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/***********************************************************************
 *
 * SOAP 1.1
 *
 **********************************************************************/
 EET_EXPORT xmlNodePtr        libeetSoap11CreateEnvelope      (xmlDocPtr doc);
 EET_EXPORT xmlNodePtr        libeetSoap11EnsureHeader        (xmlNodePtr envNode);
 EET_EXPORT xmlNodePtr        libeetSoap11AddBodyEntry        (xmlNodePtr envNode,
                                                                 xmlNodePtr entryNode);
 EET_EXPORT xmlNodePtr        libeetSoap11AddFaultEntry       (xmlNodePtr envNode,
                                                                 const xmlChar* faultCodeHref,
                                                                 const xmlChar* faultCodeLocalPart,
                                                                 const xmlChar* faultString,
                                                                 const xmlChar* faultActor);
 EET_EXPORT int               libeetSoap11CheckEnvelope       (xmlNodePtr envNode);
 EET_EXPORT xmlNodePtr        libeetSoap11GetHeader           (xmlNodePtr envNode);
 EET_EXPORT xmlNodePtr        libeetSoap11GetBody             (xmlNodePtr envNode);
 EET_EXPORT xmlSecSize        libeetSoap11GetBodyEntriesNumber(xmlNodePtr envNode);
 EET_EXPORT xmlNodePtr        libeetSoap11GetBodyEntry        (xmlNodePtr envNode,
                                                                 xmlSecSize pos);
 EET_EXPORT xmlNodePtr        libeetSoap11GetFaultEntry       (xmlNodePtr envNode);


/***********************************************************************
 *
 * SOAP 1.2
 *
 **********************************************************************/
/**
 * libeetSoap12FaultCode:
 * @libeetSoap12FaultCodeUnknown:               The fault code is not available.
 * @libeetSoap12FaultCodeVersionMismatch:       The faulting node found an
 *                                              invalid element information
 *                                              item instead of the expected
 *                                              Envelope element information item.
 * @libeetSoap12FaultCodeMustUnderstand:        An immediate child element
 *                                              information item of the SOAP
 *                                              Header element information item
 *                                              targeted at the faulting node
 *                                              that was not understood by the
 *                                              faulting node contained a SOAP
 *                                              mustUnderstand attribute
 *                                              information item with a value of "true"
 * @libeetSoap12FaultCodeDataEncodingUnknown:   A SOAP header block or SOAP
 *                                              body child element information
 *                                              item targeted at the faulting
 *                                              SOAP node is scoped with a data
 *                                              encoding that the faulting node
 *                                              does not support.
 * @libeetSoap12FaultCodeSender:                The message was incorrectly
 *                                              formed or did not contain the
 *                                              appropriate information in order
 *                                              to succeed.
 * @libeetSoap12FaultCodeReceiver:              The message could not be processed
 *                                              for reasons attributable to the
 *                                              processing of the message rather
 *                                              than to the contents of the
 *                                              message itself.
 *
 * The values of the <Value> child element information item of the
 * <Code> element information item (http://www.w3.org/TR/2003/REC-soap12-part1-20030624/#faultcodes).
 */
typedef enum {
    libeetSoap12FaultCodeUnknown = 0,
    libeetSoap12FaultCodeVersionMismatch,
    libeetSoap12FaultCodeMustUnderstand,
    libeetSoap12FaultCodeDataEncodingUnknown,
    libeetSoap12FaultCodeSender,
    libeetSoap12FaultCodeReceiver
} libeetSoap12FaultCode;

 EET_EXPORT xmlNodePtr        libeetSoap12CreateEnvelope      (xmlDocPtr doc);
 EET_EXPORT xmlNodePtr        libeetSoap12EnsureHeader        (xmlNodePtr envNode);
 EET_EXPORT xmlNodePtr        libeetSoap12AddBodyEntry        (xmlNodePtr envNode,
                                                                 xmlNodePtr entryNode);
 EET_EXPORT xmlNodePtr        libeetSoap12AddFaultEntry       (xmlNodePtr envNode,
                                                                 libeetSoap12FaultCode faultCode,
                                                                 const xmlChar* faultReasonText,
                                                                 const xmlChar* faultReasonLang,
                                                                 const xmlChar* faultNodeURI,
                                                                 const xmlChar* faultRole);
 EET_EXPORT xmlNodePtr        libeetSoap12AddFaultSubcode     (xmlNodePtr faultNode,
                                                                 const xmlChar* subCodeHref,
                                                                 const xmlChar* subCodeName);
 EET_EXPORT xmlNodePtr        libeetSoap12AddFaultReasonText  (xmlNodePtr faultNode,
                                                                 const xmlChar* faultReasonText,
                                                                 const xmlChar* faultReasonLang);
 EET_EXPORT xmlNodePtr        libeetSoap12AddFaultDetailEntry (xmlNodePtr faultNode,
                                                                 xmlNodePtr detailEntryNode);
 EET_EXPORT int               libeetSoap12CheckEnvelope       (xmlNodePtr envNode);
 EET_EXPORT xmlNodePtr        libeetSoap12GetHeader           (xmlNodePtr envNode);
 EET_EXPORT xmlNodePtr        libeetSoap12GetBody             (xmlNodePtr envNode);
 EET_EXPORT xmlSecSize        libeetSoap12GetBodyEntriesNumber(xmlNodePtr envNode);
 EET_EXPORT xmlNodePtr        libeetSoap12GetBodyEntry        (xmlNodePtr envNode,
                                                                 xmlSecSize pos);
 EET_EXPORT xmlNodePtr        libeetSoap12GetFaultEntry       (xmlNodePtr envNode);


#endif /* LIBEET_NO_SOAP */


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LIBEET_SOAP_H__ */

