/*
 * a backup soap.c of deprecatation in xmlSec library !!!
 *
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2017 Aleksey Sanin <aleksey@aleksey.com>
 */
/**
 * SECTION:soap
 * @Short_description: Simple SOAP messages parsing/creation functions.
 * @Stability: Private
 *
 */
#include "globals.h"

#ifndef LIBEET_NO_SOAP

#include <stdlib.h>
#include <string.h>

#include <libxml/tree.h>

#include <libeet/libeet.h>
#include <xmlsec/xmltree.h>
#include <libeet/soap.h>
#include <xmlsec/errors.h>

/***********************************************************************
 *
 * SOAP 1.1
 *
 **********************************************************************/
/**
 * libeetSoap11CreateEnvelope:
 * @doc:        the parent doc (might be NULL).
 *
 * Creates a new SOAP Envelope node. Caller is responsible for
 * adding the returned node to the XML document.
 *
 * XML Schema (http://schemas.xmlsoap.org/soap/envelope/):
 *
 *     <xs:element name="Envelope" type="tns:Envelope"/>
 *     <xs:complexType name="Envelope">
 *         <xs:sequence>
 *             <xs:element ref="tns:Header" minOccurs="0"/>
 *             <xs:element ref="tns:Body" minOccurs="1"/>
 *             <xs:any namespace="##other" minOccurs="0"
 *                 maxOccurs="unbounded" processContents="lax"/>
 *         </xs:sequence>
 *         <xs:anyAttribute namespace="##other" processContents="lax"/>
 *     </xs:complexType>
 *
 * Returns: pointer to newly created <soap:Envelope> node or NULL
 * if an error occurs.
 */
xmlNodePtr
libeetSoap11CreateEnvelope(xmlDocPtr doc) {
    xmlNodePtr envNode;
    xmlNodePtr bodyNode;
    xmlNsPtr ns;

    /* create Envelope node */
    envNode = xmlNewDocNode(doc, NULL, libeetNodeEnvelope, NULL);
    if(envNode == NULL) {
        //xmlSecXmlError2("xmlNewDocNode", NULL,
        //                "node=%s", xmlSecErrorsSafeString(libeetNodeEnvelope));
        fprintf(stderr, "Error: xmlNewDocNode\n");
        return(NULL);
    }

    ns = xmlNewNs(envNode, libeetSoap11Ns, NULL) ;
    if(ns == NULL) {
        //xmlSecXmlError2("xmlNewNs", NULL,
        //                "ns=%s", xmlSecErrorsSafeString(libeetSoap11Ns));
        fprintf(stderr, "Error: xmlNewNs\n");
        xmlFreeNode(envNode);
        return(NULL);
    }
    xmlSetNs(envNode, ns);

    /* add required Body node */
    bodyNode = xmlSecAddChild(envNode, libeetNodeBody, libeetSoap11Ns);
    if(bodyNode == NULL) {
        //xmlSecInternalError("xmlSecAddChild(libeetNodeBody)", NULL);
        fprintf(stderr, "Error: xmlSecAddChild(libeetNodeBody)\n");
        xmlFreeNode(envNode);
        return(NULL);
    }

    return(envNode);
}

/**
 * libeetSoap11EnsureHeader:
 * @envNode:    the pointer to <soap:Envelope> node.
 *
 * Gets the pointer to <soap:Header> node (if necessary, the node
 * is created).
 *
 * XML Schema (http://schemas.xmlsoap.org/soap/envelope/):
 *
 *     <xs:element name="Header" type="tns:Header"/>
 *     <xs:complexType name="Header">
 *         <xs:sequence>
 *             <xs:any namespace="##other" minOccurs="0"
 *                 maxOccurs="unbounded" processContents="lax"/>
 *         </xs:sequence>
 *         <xs:anyAttribute namespace="##other" processContents="lax"/>
 *     </xs:complexType>
 *
 * Returns: pointer to <soap:Header> node or NULL if an error occurs.
 */
xmlNodePtr
libeetSoap11EnsureHeader(xmlNodePtr envNode) {
    xmlNodePtr hdrNode;
    xmlNodePtr cur;

    xmlSecAssert2(envNode != NULL, NULL);

    /* try to find Header node first */
    cur = xmlSecGetNextElementNode(envNode->children);
    if((cur != NULL) && xmlSecCheckNodeName(cur, libeetNodeHeader, libeetSoap11Ns)) {
        return(cur);
    }

    /* if the first element child is not Header then it is Body */
    if((cur == NULL) || !xmlSecCheckNodeName(cur, libeetNodeBody, libeetSoap11Ns)) {
        //xmlSecInvalidNodeError(cur, libeetNodeBody, NULL);
        fprintf(stderr, "Error: InvalidNodeError\n");
        return(NULL);
    }

    /* finally add Header node before body */
    hdrNode = xmlSecAddPrevSibling(cur, libeetNodeHeader, libeetSoap11Ns);
    if(hdrNode == NULL) {
        //xmlSecInternalError("xmlSecAddPrevSibling", NULL);
        fprintf(stderr, "Error: xmlSecAddPrevSibling\n");
        return(NULL);
    }

    return(hdrNode);
}

/**
 * libeetSoap11AddBodyEntry:
 * @envNode:            the pointer to <soap:Envelope> node.
 * @entryNode:          the pointer to body entry node.
 *
 * Adds a new entry to <soap:Body> node.
 *
 * Returns: pointer to the added entry (@contentNode) or NULL if an error occurs.
 */
xmlNodePtr
libeetSoap11AddBodyEntry(xmlNodePtr envNode, xmlNodePtr entryNode) {
    xmlNodePtr bodyNode;

    xmlSecAssert2(envNode != NULL, NULL);
    xmlSecAssert2(entryNode != NULL, NULL);

    bodyNode = libeetSoap11GetBody(envNode);
    if(bodyNode == NULL) {
        //xmlSecInternalError("libeetSoap11GetBody", NULL);
        fprintf(stderr, "Error: libeetSoap11GetBody\n");
        return(NULL);
    }

    return(xmlSecAddChildNode(bodyNode, entryNode));
}

/**
 * libeetSoap11AddFaultEntry:
 * @envNode:            the pointer to <soap:Envelope> node.
 * @faultCodeHref:      the fault code QName href (must be known in th context of
 *                      <soap:Body> node).
 * @faultCodeLocalPart: the fault code QName LocalPart.
 * @faultString:        the human readable explanation of the fault.
 * @faultActor:         the information about who caused the fault (might be NULL).
 *
 * Adds <soap:Fault> entry to the @envNode. Note that only one <soap:Fault>
 * entry is allowed.
 *
 * XML Schema (http://schemas.xmlsoap.org/soap/envelope/):
 *
 *     <xs:element name="Fault" type="tns:Fault"/>
 *     <xs:complexType name="Fault" final="extension">
 *         <xs:sequence>
 *             <xs:element name="faultcode" type="xs:QName"/>
 *             <xs:element name="faultstring" type="xs:string"/>
 *             <xs:element name="faultactor" type="xs:anyURI" minOccurs="0"/>
 *             <xs:element name="detail" type="tns:detail" minOccurs="0"/>
 *         </xs:sequence>
 *     </xs:complexType>
 *     <xs:complexType name="detail">
 *         <xs:sequence>
 *             <xs:any namespace="##any" minOccurs="0" maxOccurs="unbounded"
 *                 processContents="lax"/>
 *         </xs:sequence>
 *         <xs:anyAttribute namespace="##any" processContents="lax"/>
 *     </xs:complexType>
 *
 * Returns: pointer to the added entry or NULL if an error occurs.
 */
xmlNodePtr
libeetSoap11AddFaultEntry(xmlNodePtr envNode, const xmlChar* faultCodeHref,
                          const xmlChar* faultCodeLocalPart,
                          const xmlChar* faultString, const xmlChar* faultActor) {
    xmlNodePtr bodyNode;
    xmlNodePtr faultNode;
    xmlNodePtr cur;
    xmlChar* qname;

    xmlSecAssert2(envNode != NULL, NULL);
    xmlSecAssert2(faultCodeLocalPart != NULL, NULL);
    xmlSecAssert2(faultString != NULL, NULL);

    /* get Body node */
    bodyNode = libeetSoap11GetBody(envNode);
    if(bodyNode == NULL) {
        //xmlSecInternalError("libeetSoap11GetBody", NULL);
        fprintf(stderr, "Error: libeetSoap11GetBody\n");
        return(NULL);
    }

    /* check that we don't have Fault node already */
    faultNode = xmlSecFindChild(bodyNode, libeetNodeFault, libeetSoap11Ns);
    if(faultNode != NULL) {
        //libeetNodeAlreadyPresentError(bodyNode, libeetNodeFault, NULL);
        fprintf(stderr, "Error: NodeAlreadyPresentError\n");
        return(NULL);
    }

    /* add Fault node */
    faultNode = xmlSecAddChild(bodyNode, libeetNodeFault, libeetSoap11Ns);
    if(faultNode == NULL) {
        //xmlSecInternalError("xmlSecAddChild(libeetNodeFault)", NULL);
        fprintf(stderr, "Error: xmlSecAddChild(libeetNodeFault)\n");
        return(NULL);
    }

    /* add faultcode node */
    cur = xmlSecAddChild(faultNode, libeetNodeFaultCode, libeetSoap11Ns);
    if(cur == NULL) {
        //xmlSecInternalError("xmlSecAddChild(libeetNodeFaultCode)", NULL);
        fprintf(stderr, "Error: xmlSecAddChild(libeetNodeFaultCode)\n");
        xmlUnlinkNode(faultNode);
        xmlFreeNode(faultNode);
        return(NULL);
    }

    /* create qname for fault code */
    qname = xmlSecGetQName(cur, faultCodeHref, faultCodeLocalPart);
    if(qname == NULL) {
        //xmlSecXmlError2("xmlSecGetQName", NULL,
        //                "node=%s", xmlSecErrorsSafeString(cur->name));
        fprintf(stderr, "Error: xmlSecGetQName\n");
        xmlUnlinkNode(faultNode);
        xmlFreeNode(faultNode);
        return(NULL);
    }

    /* set faultcode value */
    xmlNodeSetContent(cur, qname);
    eetFree(qname);

    /* add faultstring node */
    cur = xmlSecAddChild(faultNode, libeetNodeFaultString, libeetSoap11Ns);
    if(cur == NULL) {
        //xmlSecInternalError("xmlSecAddChild(libeetNodeFaultString)", NULL);
        fprintf(stderr, "Error: xmlSecAddChild(libeetNodeFaultString)\n");
        xmlUnlinkNode(faultNode);
        xmlFreeNode(faultNode);
        return(NULL);
    }

    /* set faultstring node */
    xmlNodeSetContent(cur, faultString);

    if(faultActor != NULL) {
        /* add faultactor node */
        cur = xmlSecAddChild(faultNode, libeetNodeFaultActor, libeetSoap11Ns);
        if(cur == NULL) {
            //xmlSecInternalError("xmlSecAddChild(libeetNodeFaultActor)", NULL);
            fprintf(stderr, "Error: xmlSecAddChild(libeetNodeFaultActor)\n");
            xmlUnlinkNode(faultNode);
            xmlFreeNode(faultNode);
            return(NULL);
        }

        /* set faultactor node */
        xmlNodeSetContent(cur, faultActor);
    }

    return(faultNode);
}

/**
 * libeetSoap11CheckEnvelope:
 * @envNode:    the pointer to <soap:Envelope> node.
 *
 * Validates <soap:Envelope> node structure.
 *
 * Returns: 1 if @envNode has a valid <soap:Envelope> element, 0 if it is
 * not valid or a negative value if an error occurs.
 */
int
libeetSoap11CheckEnvelope(xmlNodePtr envNode) {
    xmlNodePtr cur;

    xmlSecAssert2(envNode != NULL, -1);

    /* verify envNode itself */
    if(!xmlSecCheckNodeName(envNode, libeetNodeEnvelope, libeetSoap11Ns)) {
        //xmlSecInvalidNodeError(envNode, libeetNodeEnvelope, NULL);
        fprintf(stderr, "Error: InvalidNodeError\n");
        return(0);
    }

    /* optional Header node first */
    cur = xmlSecGetNextElementNode(envNode->children);
    if((cur != NULL) && xmlSecCheckNodeName(cur, libeetNodeHeader, libeetSoap11Ns)) {
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* required Body node is next */
    if((cur == NULL) || !xmlSecCheckNodeName(cur, libeetNodeBody, libeetSoap11Ns)) {
        //xmlSecInvalidNodeError(cur, libeetNodeBody, NULL);
        fprintf(stderr, "Error: InvalidNodeError\n");
        return(0);
    }

    return(1);
}

/**
 * libeetSoap11GetHeader:
 * @envNode:    the pointer to <soap:Envelope> node.
 *
 * Gets pointer to the <soap:Header> node.
 *
 * Returns: pointer to <soap:Header> node or NULL if an error occurs.
 */
xmlNodePtr
libeetSoap11GetHeader(xmlNodePtr envNode) {
    xmlNodePtr cur;

    xmlSecAssert2(envNode != NULL, NULL);

    /* optional Header node is first */
    cur = xmlSecGetNextElementNode(envNode->children);
    if((cur != NULL) && xmlSecCheckNodeName(cur, libeetNodeHeader, libeetSoap11Ns)) {
        return(cur);
    }

    return(NULL);
}

/**
 * libeetSoap11GetBody:
 * @envNode:    the pointer to <soap:Envelope> node.
 *
 * Gets pointer to the <soap:Body> node.
 *
 * Returns: pointer to <soap:Body> node or NULL if an error occurs.
 */
xmlNodePtr
libeetSoap11GetBody(xmlNodePtr envNode) {
    xmlNodePtr cur;

    xmlSecAssert2(envNode != NULL, NULL);

    /* optional Header node first */
    cur = xmlSecGetNextElementNode(envNode->children);
    if((cur != NULL) && xmlSecCheckNodeName(cur, libeetNodeHeader, libeetSoap11Ns)) {
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* Body node is next */
    if((cur == NULL) || !xmlSecCheckNodeName(cur, libeetNodeBody, libeetSoap11Ns)) {
        //xmlSecInvalidNodeError(cur, libeetNodeBody, NULL);
        fprintf(stderr, "Error: InvalidNodeError\n");
        return(NULL);
    }

    return(cur);
}

/**
 * libeetSoap11GetBodyEntriesNumber:
 * @envNode:    the pointer to <soap:Envelope> node.
 *
 * Gets the number of body entries.
 *
 * Returns: the number of body entries.
 */
xmlSecSize
libeetSoap11GetBodyEntriesNumber(xmlNodePtr envNode) {
    xmlSecSize number = 0;
    xmlNodePtr bodyNode;
    xmlNodePtr cur;

    xmlSecAssert2(envNode != NULL, 0);

    /* get Body node */
    bodyNode = libeetSoap11GetBody(envNode);
    if(bodyNode == NULL) {
        //xmlSecInternalError("libeetSoap11GetBody", NULL);
        fprintf(stderr, "Error: libeetSoap11GetBody\n");
        return(0);
    }

    cur = xmlSecGetNextElementNode(bodyNode->children);
    while(cur != NULL) {
        number++;
        cur = xmlSecGetNextElementNode(cur->next);
    }

    return(number);
}

/**
 * libeetSoap11GetBodyEntry:
 * @envNode:    the pointer to <soap:Envelope> node.
 * @pos:        the body entry number.
 *
 * Gets the body entry number @pos.
 *
 * Returns: pointer to body entry node or NULL if an error occurs.
 */
xmlNodePtr
libeetSoap11GetBodyEntry(xmlNodePtr envNode, xmlSecSize pos) {
    xmlNodePtr bodyNode;
    xmlNodePtr cur;

    xmlSecAssert2(envNode != NULL, NULL);

    /* get Body node */
    bodyNode = libeetSoap11GetBody(envNode);
    if(bodyNode == NULL) {
        //xmlSecInternalError("libeetSoap11GetBody", NULL);
        fprintf(stderr, "Error: libeetSoap11GetBody\n");
        return(NULL);
    }

    cur = xmlSecGetNextElementNode(bodyNode->children);
    while((cur != NULL) && (pos > 0)) {
        pos--;
        cur = xmlSecGetNextElementNode(cur->next);
    }

    return(cur);
}

/**
 * libeetSoap11GetFaultEntry:
 * @envNode:    the pointer to <soap:Envelope> node.
 *
 * Gets the Fault entry (if any).
 *
 * Returns: pointer to Fault entry or NULL if it does not exist.
 */
xmlNodePtr
libeetSoap11GetFaultEntry(xmlNodePtr envNode) {
    xmlNodePtr bodyNode;

    xmlSecAssert2(envNode != NULL, NULL);

    /* get Body node */
    bodyNode = libeetSoap11GetBody(envNode);
    if(bodyNode == NULL) {
        //xmlSecInternalError("libeetSoap11GetBody", NULL);
        fprintf(stderr, "Error: libeetSoap11GetBodyt \n");
        return(NULL);
    }

    return(xmlSecFindChild(bodyNode, libeetNodeFault, libeetSoap11Ns));
}


/***********************************************************************
 *
 * SOAP 1.2
 *
 **********************************************************************/
static const xmlSecQName2IntegerInfo glibeetSoap12FaultCodeInfo[] =
{
    { libeetSoap12Ns, libeetSoapFaultCodeVersionMismatch,
      libeetSoap12FaultCodeVersionMismatch },
    { libeetSoap12Ns, libeetSoapFaultCodeMustUnderstand,
      libeetSoap12FaultCodeMustUnderstand },
    { libeetSoap12Ns, libeetSoapFaultDataEncodningUnknown,
      libeetSoap12FaultCodeDataEncodingUnknown },
    { libeetSoap12Ns, libeetSoapFaultCodeSender,
      libeetSoap12FaultCodeSender },
    { libeetSoap12Ns, libeetSoapFaultCodeReceiver,
      libeetSoap12FaultCodeReceiver },
    { NULL, NULL, 0 }   /* MUST be last in the list */
};

/**
 * libeetSoap12CreateEnvelope:
 * @doc:        the parent doc (might be NULL).
 *
 * Creates a new SOAP 1.2 Envelope node. Caller is responsible for
 * adding the returned node to the XML document.
 *
 * XML Schema (http://www.w3.org/2003/05/soap-envelope):
 *
 *     <xs:element name="Envelope" type="tns:Envelope"/>
 *     <xs:complexType name="Envelope">
 *         <xs:sequence>
 *             <xs:element ref="tns:Header" minOccurs="0"/>
 *             <xs:element ref="tns:Body" minOccurs="1"/>
 *         </xs:sequence>
 *         <xs:anyAttribute namespace="##other" processContents="lax"/>
 *     </xs:complexType>
 *
 * Returns: pointer to newly created <soap:Envelope> node or NULL
 * if an error occurs.
 */
xmlNodePtr
libeetSoap12CreateEnvelope(xmlDocPtr doc) {
    xmlNodePtr envNode;
    xmlNodePtr bodyNode;
    xmlNsPtr ns;

    /* create Envelope node */
    envNode = xmlNewDocNode(doc, NULL, libeetNodeEnvelope, NULL);
    if(envNode == NULL) {
        //xmlSecXmlError2("xmlNewDocNode", NULL,
        //                "node=%s", xmlSecErrorsSafeString(libeetNodeEnvelope));
        fprintf(stderr, "Error: xmlNewDocNode\n");
        return(NULL);
    }

    ns = xmlNewNs(envNode, libeetSoap12Ns, NULL) ;
    if(ns == NULL) {
        //xmlSecXmlError2("xmlNewNs", NULL,
        //                "ns=%s", xmlSecErrorsSafeString(libeetSoap12Ns));
        fprintf(stderr, "Error: xmlNewNs\n");
        xmlFreeNode(envNode);
        return(NULL);
    }
    xmlSetNs(envNode, ns);

    /* add required Body node */
    bodyNode = xmlSecAddChild(envNode, libeetNodeBody, libeetSoap12Ns);
    if(bodyNode == NULL) {
        //xmlSecInternalError("xmlSecAddChild(libeetNodeBody)", NULL);
        fprintf(stderr, "Error: xmlSecAddChild(libeetNodeBody)\n");
        xmlFreeNode(envNode);
        return(NULL);
    }

    return(envNode);
}

/**
 * libeetSoap12EnsureHeader:
 * @envNode:    the pointer to <soap:Envelope> node.
 *
 * Gets the pointer to <soap:Header> node (if necessary, the node
 * is created).
 *
 * XML Schema (http://www.w3.org/2003/05/soap-envelope):
 *
 *     <xs:element name="Header" type="tns:Header"/>
 *     <xs:complexType name="Header">
 *         <xs:sequence>
 *             <xs:any namespace="##any" processContents="lax"
 *                     minOccurs="0" maxOccurs="unbounded"/>
 *         </xs:sequence>
 *         <xs:anyAttribute namespace="##other" processContents="lax"/>
 *     </xs:complexType>
 *
 * Returns: pointer to <soap:Header> node or NULL if an error occurs.
 */
xmlNodePtr
libeetSoap12EnsureHeader(xmlNodePtr envNode) {
    xmlNodePtr hdrNode;
    xmlNodePtr cur;

    xmlSecAssert2(envNode != NULL, NULL);

    /* try to find Header node first */
    cur = xmlSecGetNextElementNode(envNode->children);
    if((cur != NULL) && xmlSecCheckNodeName(cur, libeetNodeHeader, libeetSoap12Ns)) {
        return(cur);
    }

    /* if the first element child is not Header then it is Body */
    if((cur == NULL) || !xmlSecCheckNodeName(cur, libeetNodeBody, libeetSoap12Ns)) {
        //xmlSecInvalidNodeError(cur, libeetNodeBody, NULL);
        fprintf(stderr, "Error: InvalidNodeError\n");
        return(NULL);
    }

    /* finally add Header node before body */
    hdrNode = xmlSecAddPrevSibling(cur, libeetNodeHeader, libeetSoap12Ns);
    if(hdrNode == NULL) {
        //xmlSecInternalError("xmlSecAddPrevSibling", NULL);
        fprintf(stderr, "Error: xmlSecAddPrevSibling\n");
        return(NULL);
    }

    return(hdrNode);
}

/**
 * libeetSoap12AddBodyEntry:
 * @envNode:            the pointer to <soap:Envelope> node.
 * @entryNode:          the pointer to body entry node.
 *
 * Adds a new entry to <soap:Body> node.
 *
 * XML Schema (http://www.w3.org/2003/05/soap-envelope):
 *
 *     <xs:element name="Body" type="tns:Body"/>
 *     <xs:complexType name="Body">
 *         <xs:sequence>
 *             <xs:any namespace="##any" processContents="lax"
 *                     minOccurs="0" maxOccurs="unbounded"/>
 *         </xs:sequence>
 *         <xs:anyAttribute namespace="##other" processContents="lax"/>
 *     </xs:complexType>
 *
 * Returns: pointer to the added entry (@contentNode) or NULL if an error occurs.
 */
xmlNodePtr
libeetSoap12AddBodyEntry(xmlNodePtr envNode, xmlNodePtr entryNode) {
    xmlNodePtr bodyNode;

    xmlSecAssert2(envNode != NULL, NULL);
    xmlSecAssert2(entryNode != NULL, NULL);

    bodyNode = libeetSoap12GetBody(envNode);
    if(bodyNode == NULL) {
        //xmlSecInternalError("libeetSoap12GetBody", NULL);
        fprintf(stderr, "Error: libeetSoap12GetBody\n");
        return(NULL);
    }

    return(xmlSecAddChildNode(bodyNode, entryNode));
}

/**
 * libeetSoap12AddFaultEntry:
 * @envNode:            the pointer to <soap:Envelope> node.
 * @faultCode:          the fault code.
 * @faultReasonText:    the human readable explanation of the fault.
 * @faultReasonLang:    the language (xml:lang) for @faultReason string.
 * @faultNodeURI:       the more preciese information about fault source
 *                      (might be NULL).
 * @faultRole:          the role the node was operating in at the point
 *                      the fault occurred (might be NULL).
 *
 * Adds <soap:Fault> entry to the @envNode. Note that only one <soap:Fault>
 * entry is allowed.
 *
 * XML Schema (http://www.w3.org/2003/05/soap-envelope):
 *
 *     <xs:element name="Fault" type="tns:Fault"/>
 *     <xs:complexType name="Fault" final="extension">
 *         <xs:sequence>
 *             <xs:element name="Code" type="tns:faultcode"/>
 *             <xs:element name="Reason" type="tns:faultreason"/>
 *             <xs:element name="Node" type="xs:anyURI" minOccurs="0"/>
 *             <xs:element name="Role" type="xs:anyURI" minOccurs="0"/>
 *             <xs:element name="Detail" type="tns:detail" minOccurs="0"/>
 *         </xs:sequence>
 *     </xs:complexType>
 *
 *     <xs:complexType name="faultcode">
 *         <xs:sequence>
 *             <xs:element name="Value" type="tns:faultcodeEnum"/>
 *             <xs:element name="Subcode" type="tns:subcode" minOccurs="0"/>
 *         </xs:sequence>
 *     </xs:complexType>
 *
 *     <xs:complexType name="faultreason">
 *         <xs:sequence>
 *             <xs:element name="Text" type="tns:reasontext"
 *                         minOccurs="1" maxOccurs="unbounded"/>
 *         </xs:sequence>
 *     </xs:complexType>
 *
 *     <xs:complexType name="reasontext">
 *         <xs:simpleContent>
 *             <xs:extension base="xs:string">
 *                 <xs:attribute ref="xml:lang" use="required"/>
 *             </xs:extension>
 *         </xs:simpleContent>
 *     </xs:complexType>
 *
 *     <xs:simpleType name="faultcodeEnum">
 *         <xs:restriction base="xs:QName">
 *             <xs:enumeration value="tns:DataEncodingUnknown"/>
 *             <xs:enumeration value="tns:MustUnderstand"/>
 *             <xs:enumeration value="tns:Receiver"/>
 *             <xs:enumeration value="tns:Sender"/>
 *             <xs:enumeration value="tns:VersionMismatch"/>
 *         </xs:restriction>
 *     </xs:simpleType>
 *
 *     <xs:complexType name="subcode">
 *         <xs:sequence>
 *             <xs:element name="Value" type="xs:QName"/>
 *             <xs:element name="Subcode" type="tns:subcode" minOccurs="0"/>
 *         </xs:sequence>
 *     </xs:complexType>
 *
 *     <xs:complexType name="detail">
 *         <xs:sequence>
 *             <xs:any namespace="##any" processContents="lax"
 *                 minOccurs="0" maxOccurs="unbounded"/>
 *         </xs:sequence>
 *         <xs:anyAttribute namespace="##other" processContents="lax"/>
 *     </xs:complexType>
 *
 * Returns: pointer to the added entry or NULL if an error occurs.
 */
xmlNodePtr
libeetSoap12AddFaultEntry(xmlNodePtr envNode, libeetSoap12FaultCode faultCode,
                         const xmlChar* faultReasonText, const xmlChar* faultReasonLang,
                         const xmlChar* faultNodeURI, const xmlChar* faultRole) {
    xmlNodePtr bodyNode;
    xmlNodePtr faultNode;
    xmlNodePtr cur;
    int ret;

    xmlSecAssert2(envNode != NULL, NULL);
    xmlSecAssert2(faultCode != libeetSoap12FaultCodeUnknown, NULL);
    xmlSecAssert2(faultReasonText != NULL, NULL);
    xmlSecAssert2(faultReasonLang != NULL, NULL);

    /* get Body node */
    bodyNode = libeetSoap12GetBody(envNode);
    if(bodyNode == NULL) {
        //xmlSecInternalError("libeetSoap12GetBody", NULL);
        fprintf(stderr, "Error: libeetSoap12GetBody\n");
        return(NULL);
    }

    /* check that we don't have Fault node already */
    faultNode = xmlSecFindChild(bodyNode, libeetNodeFault, libeetSoap12Ns);
    if(faultNode != NULL) {
        //libeetNodeAlreadyPresentError(bodyNode, libeetNodeFault, NULL);
        fprintf(stderr, "Error: bodyNode(NodeFault)\n");
        return(NULL);
    }

    /* add Fault node */
    faultNode = xmlSecAddChild(bodyNode, libeetNodeFault, libeetSoap12Ns);
    if(faultNode == NULL) {
        //xmlSecInternalError("xmlSecAddChild(libeetNodeFault)", NULL);
        fprintf(stderr, "Error: xmlSecAddChild(libeetNodeFault)\n");
        return(NULL);
    }

    /* add Code node */
    cur = xmlSecAddChild(faultNode, libeetNodeCode, libeetSoap12Ns);
    if(cur == NULL) {
        //xmlSecInternalError("xmlSecAddChild(libeetNodeCode)", NULL);
        fprintf(stderr, "Error: xmlSecAddChild(libeetNodeCode)\n");
        xmlUnlinkNode(faultNode);
        xmlFreeNode(faultNode);
        return(NULL);
    }

    /* write the fault code in Value child */
    ret = xmlSecQName2IntegerNodeWrite(glibeetSoap12FaultCodeInfo, cur,
                                       libeetNodeValue, libeetSoap12Ns,
                                       faultCode);
    if(ret < 0) {
        //xmlSecInternalError2("xmlSecQName2IntegerNodeWrite", NULL,
        //                     "faultCode=%d", faultCode);
        fprintf(stderr, "Error: xmlSecQName2IntegerNodeWrite faultCode=%d\n", faultCode);
        xmlUnlinkNode(faultNode);
        xmlFreeNode(faultNode);
        return(NULL);
    }

    /* add Reason node */
    cur = xmlSecAddChild(faultNode, libeetNodeReason, libeetSoap12Ns);
    if(cur == NULL) {
        //xmlSecInternalError("xmlSecAddChild(libeetNodeReason)", NULL);
        fprintf(stderr, "Error: xmlSecAddChild(libeetNodeReason)\n");
        xmlUnlinkNode(faultNode);
        xmlFreeNode(faultNode);
        return(NULL);
    }

    /* Add Reason/Text node */
    if(libeetSoap12AddFaultReasonText(faultNode, faultReasonText, faultReasonLang) == NULL) {
        //xmlSecInternalError2("libeetSoap12AddFaultReasonText", NULL,
        //                     "text=%s", xmlSecErrorsSafeString(faultReasonText));
        fprintf(stderr, "Error: libeetSoap12AddFaultReasonText\n");
        xmlUnlinkNode(faultNode);
        xmlFreeNode(faultNode);
        return(NULL);
    }

    if(faultNodeURI != NULL) {
        /* add Node node */
        cur = xmlSecAddChild(faultNode, libeetNodeNode, libeetSoap12Ns);
        if(cur == NULL) {
            //xmlSecInternalError("xmlSecAddChild(libeetNodeNode)", NULL);
            fprintf(stderr, "Error: xmlSecAddChild(libeetNodeNode)\n");
            xmlUnlinkNode(faultNode);
            xmlFreeNode(faultNode);
            return(NULL);
        }
        xmlNodeSetContent(cur, faultNodeURI);
    }

    if(faultRole != NULL) {
        /* add Role node */
        cur = xmlSecAddChild(faultNode, libeetNodeRole, libeetSoap12Ns);
        if(cur == NULL) {
            //xmlSecInternalError("xmlSecAddChild(libeetNodeRole)", NULL);
            fprintf(stderr, "Error: xmlSecAddChild(libeetNodeRole)\n");
            xmlUnlinkNode(faultNode);
            xmlFreeNode(faultNode);
            return(NULL);
        }
        xmlNodeSetContent(cur, faultRole);
    }

    return(faultNode);
}

/**
 * libeetSoap12AddFaultSubcode:
 * @faultNode:          the pointer to <Fault> node.
 * @subCodeHref:        the subcode href.
 * @subCodeName:        the subcode name.
 *
 * Adds a new <Subcode> node to the <Code> node or the last <Subcode> node.
 *
 * Returns: a pointer to the newly created <Subcode> node or NULL if an error
 * occurs.
 */
xmlNodePtr
libeetSoap12AddFaultSubcode(xmlNodePtr faultNode, const xmlChar* subCodeHref, const xmlChar* subCodeName) {
    xmlNodePtr cur, subcodeNode, valueNode;
    xmlChar* qname;

    xmlSecAssert2(faultNode != NULL, NULL);
    xmlSecAssert2(subCodeHref != NULL, NULL);
    xmlSecAssert2(subCodeName != NULL, NULL);

    /* Code node is the first children in Fault node */
    cur = xmlSecGetNextElementNode(faultNode->children);
    if((cur == NULL) || !xmlSecCheckNodeName(cur, libeetNodeCode, libeetSoap12Ns)) {
        //xmlSecInvalidNodeError(cur, libeetNodeCode, NULL);
        fprintf(stderr, "Error: nodeError\n");
        return(NULL);
    }

    /* find the Code or Subcode node that does not have Subcode child */
    while(1) {
        xmlNodePtr tmp;

        tmp = xmlSecFindChild(cur, libeetNodeSubcode, libeetSoap12Ns);
        if(tmp != NULL) {
            cur = tmp;
        } else {
            break;
        }
    }
    xmlSecAssert2(cur != NULL, NULL);

    /* add Subcode node */
    subcodeNode = xmlSecAddChild(cur, libeetNodeSubcode, libeetSoap12Ns);
    if(subcodeNode == NULL) {
        //xmlSecInternalError("xmlSecAddChild(libeetNodeSubcode)", NULL);
        fprintf(stderr, "Error: xmlSecAddChild(libeetNodeSubcode)\n");
        return(NULL);
    }

    /* add Value node */
    valueNode = xmlSecAddChild(subcodeNode, libeetNodeValue, libeetSoap12Ns);
    if(valueNode == NULL) {
        //xmlSecInternalError("xmlSecAddChild(libeetNodeValue)", NULL);
        fprintf(stderr, "Error: xmlSecAddChild(libeetNodeValue)\n");
        xmlUnlinkNode(subcodeNode);
        xmlFreeNode(subcodeNode);
        return(NULL);
    }

    /* create qname for fault code */
    qname = xmlSecGetQName(cur, subCodeHref, subCodeName);
    if(qname == NULL) {
        //xmlSecXmlError2("xmlSecGetQName", NULL,
        //                "node=%s", xmlSecErrorsSafeString(cur->name));
        fprintf(stderr, "Error: xmlSecGetQName\n");
        xmlUnlinkNode(subcodeNode);
        xmlFreeNode(subcodeNode);
        return(NULL);
    }

    /* set result qname in Value node */
    xmlNodeSetContent(cur, qname);
    if(qname != subCodeName) {
        eetFree(qname);
    }

    return(subcodeNode);
}

/**
 * libeetSoap12AddFaultReasonText:
 * @faultNode:          the pointer to <Fault> node.
 * @faultReasonText:    the new reason text.
 * @faultReasonLang:    the new reason xml:lang attribute.
 *
 * Adds a new Text node to the Fault/Reason node.
 *
 * Returns: a pointer to the newly created <Text> node or NULL if an error
 * occurs.
 */
xmlNodePtr
libeetSoap12AddFaultReasonText(xmlNodePtr faultNode, const xmlChar* faultReasonText,
                               const xmlChar* faultReasonLang) {
    xmlNodePtr reasonNode;
    xmlNodePtr textNode;

    xmlSecAssert2(faultNode != NULL, NULL);
    xmlSecAssert2(faultReasonText != NULL, NULL);
    xmlSecAssert2(faultReasonLang != NULL, NULL);

    /* find Reason node */
    reasonNode = xmlSecFindChild(faultNode,  libeetNodeReason, libeetSoap12Ns);
    if(reasonNode == NULL) {
        //xmlSecInternalError("xmlSecFindChild(libeetNodeReason)", NULL);
        fprintf(stderr, "Error: xmlSecFindChild(libeetNodeReason)\n");
        return(NULL);
    }

    /* add Text node */
    textNode = xmlSecAddChild(reasonNode, libeetNodeText, libeetSoap12Ns);
    if(textNode == NULL) {
        //xmlSecInternalError("xmlSecAddChild(libeetNodeText)", NULL);
        fprintf(stderr, "Error: xmlSecAddChild(libeetNodeText)\n");
        return(NULL);
    }
    xmlNodeSetContent(textNode, faultReasonText);
    xmlNodeSetLang(textNode, faultReasonLang);

    return(textNode);
}

/**
 * libeetSoap12AddFaultDetailEntry:
 * @faultNode:          the pointer to <Fault> node.
 * @detailEntryNode:    the pointer to detail entry node.
 *
 * Adds a new child to the Detail child element of @faultNode.
 *
 * Returns: pointer to the added child (@detailEntryNode) or NULL if an error
 * occurs.
 */
xmlNodePtr
libeetSoap12AddFaultDetailEntry(xmlNodePtr faultNode, xmlNodePtr detailEntryNode) {
    xmlNodePtr detailNode;

    xmlSecAssert2(faultNode != NULL, NULL);
    xmlSecAssert2(detailEntryNode != NULL, NULL);

    /* find Detail node and add it if needed */
    detailNode = xmlSecFindChild(faultNode,  libeetNodeDetail, libeetSoap12Ns);
    if(detailNode == NULL) {
        detailNode = xmlSecAddChild(faultNode, libeetNodeDetail, libeetSoap12Ns);
        if(detailNode == NULL) {
            //xmlSecInternalError("xmlSecAddChild(libeetNodeDetail)", NULL);
            fprintf(stderr, "Error: xmlSecAddChild(libeetNodeDetail)\n");
            return(NULL);
        }
    }

    return(xmlSecAddChildNode(detailNode, detailEntryNode));
}

/**
 * libeetSoap12CheckEnvelope:
 * @envNode:    the pointer to <soap:Envelope> node.
 *
 * Validates <soap:Envelope> node structure.
 *
 * Returns: 1 if @envNode has a valid <soap:Envelope> element, 0 if it is
 * not valid or a negative value if an error occurs.
 */
int
libeetSoap12CheckEnvelope(xmlNodePtr envNode) {
    xmlNodePtr cur;

    xmlSecAssert2(envNode != NULL, -1);

    /* verify envNode itself */
    if(!xmlSecCheckNodeName(envNode, libeetNodeEnvelope, libeetSoap12Ns)) {
        //xmlSecInvalidNodeError(envNode, libeetNodeEnvelope, NULL);
        fprintf(stderr, "Error: InvalidNodeError\n");
        return(0);
    }

    /* optional Header node first */
    cur = xmlSecGetNextElementNode(envNode->children);
    if((cur != NULL) && xmlSecCheckNodeName(cur, libeetNodeHeader, libeetSoap12Ns)) {
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* required Body node is next */
    if((cur == NULL) || !xmlSecCheckNodeName(cur, libeetNodeBody, libeetSoap12Ns)) {
        //xmlSecInvalidNodeError(cur, libeetNodeBody, NULL);
        fprintf(stderr, "Error: InvalidNodeError\n");
        return(0);
    }

    return(1);
}

/**
 * libeetSoap12GetHeader:
 * @envNode:    the pointer to <soap:Envelope> node.
 *
 * Gets pointer to the <soap:Header> node.
 *
 * Returns: pointer to <soap:Header> node or NULL if an error occurs.
 */
xmlNodePtr
libeetSoap12GetHeader(xmlNodePtr envNode) {
    xmlNodePtr cur;

    xmlSecAssert2(envNode != NULL, NULL);

    /* optional Header node is first */
    cur = xmlSecGetNextElementNode(envNode->children);
    if((cur != NULL) && xmlSecCheckNodeName(cur, libeetNodeHeader, libeetSoap12Ns)) {
        return(cur);
    }

    return(NULL);
}

/**
 * libeetSoap12GetBody:
 * @envNode:    the pointer to <soap:Envelope> node.
 *
 * Gets pointer to the <soap:Body> node.
 *
 * Returns: pointer to <soap:Body> node or NULL if an error occurs.
 */
xmlNodePtr
libeetSoap12GetBody(xmlNodePtr envNode) {
    xmlNodePtr cur;

    xmlSecAssert2(envNode != NULL, NULL);

    /* optional Header node first */
    cur = xmlSecGetNextElementNode(envNode->children);
    if((cur != NULL) && xmlSecCheckNodeName(cur, libeetNodeHeader, libeetSoap12Ns)) {
        cur = xmlSecGetNextElementNode(cur->next);
    }

    /* Body node is next */
    if((cur == NULL) || !xmlSecCheckNodeName(cur, libeetNodeBody, libeetSoap12Ns)) {
        //xmlSecInvalidNodeError(cur, libeetNodeBody, NULL);
        fprintf(stderr, "Error: InvalidNodeError\n");
        return(NULL);
    }

    return(cur);
}

/**
 * libeetSoap12GetBodyEntriesNumber:
 * @envNode:    the pointer to <soap:Envelope> node.
 *
 * Gets the number of body entries.
 *
 * Returns: the number of body entries.
 */
xmlSecSize
libeetSoap12GetBodyEntriesNumber(xmlNodePtr envNode) {
    xmlSecSize number = 0;
    xmlNodePtr bodyNode;
    xmlNodePtr cur;

    xmlSecAssert2(envNode != NULL, 0);

    /* get Body node */
    bodyNode = libeetSoap12GetBody(envNode);
    if(bodyNode == NULL) {
        //xmlSecInternalError("libeetSoap12GetBody", NULL);
        fprintf(stderr, "Error: libeetSoap12GetBody\n");
        return(0);
    }

    cur = xmlSecGetNextElementNode(bodyNode->children);
    while(cur != NULL) {
        number++;
        cur = xmlSecGetNextElementNode(cur->next);
    }

    return(number);
}

/**
 * libeetSoap12GetBodyEntry:
 * @envNode:    the pointer to <soap:Envelope> node.
 * @pos:        the body entry number.
 *
 * Gets the body entry number @pos.
 *
 * Returns: pointer to body entry node or NULL if an error occurs.
 */
xmlNodePtr
libeetSoap12GetBodyEntry(xmlNodePtr envNode, xmlSecSize pos) {
    xmlNodePtr bodyNode;
    xmlNodePtr cur;

    xmlSecAssert2(envNode != NULL, NULL);

    /* get Body node */
    bodyNode = libeetSoap12GetBody(envNode);
    if(bodyNode == NULL) {
        //xmlSecInternalError("libeetSoap12GetBody", NULL);
        fprintf(stderr, "Error: libeetSoap12GetBody\n");
        return(NULL);
    }

    cur = xmlSecGetNextElementNode(bodyNode->children);
    while((cur != NULL) && (pos > 0)) {
        pos--;
        cur = xmlSecGetNextElementNode(cur->next);
    }

    return(cur);
}

/**
 * libeetSoap12GetFaultEntry:
 * @envNode:    the pointer to <soap:Envelope> node.
 *
 * Gets the Fault entry (if any).
 *
 * Returns: pointer to Fault entry or NULL if it does not exist.
 */
xmlNodePtr
libeetSoap12GetFaultEntry(xmlNodePtr envNode) {
    xmlNodePtr bodyNode;

    xmlSecAssert2(envNode != NULL, NULL);

    /* get Body node */
    bodyNode = libeetSoap12GetBody(envNode);
    if(bodyNode == NULL) {
        //xmlSecInternalError("libeetSoap12GetBody", NULL);
        fprintf(stderr, "Error: libeetSoap12GetBody\n");
        return(NULL);
    }

    return(xmlSecFindChild(bodyNode, libeetNodeFault, libeetSoap12Ns));
}

#endif /* LIBEET_NO_SOAP */


