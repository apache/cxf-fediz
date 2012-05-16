/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.cxf.fediz.service.idp;

import java.io.StringWriter;
import java.security.cert.X509Certificate;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Element;

import org.apache.cxf.Bus;
import org.apache.cxf.binding.soap.SoapBindingConstants;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.service.model.BindingOperationInfo;
import org.apache.cxf.staxutils.StaxUtils;
import org.apache.cxf.staxutils.W3CDOMStreamWriter;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.cxf.ws.security.trust.STSClient;
import org.apache.cxf.ws.security.trust.STSUtils;
import org.apache.ws.security.components.crypto.Crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IdpSTSClient extends STSClient {

    private static final Logger LOG = LoggerFactory.getLogger(IdpSTSClient.class);

    public IdpSTSClient(Bus b) {
        super(b);
    }

    public String requestSecurityTokenResponse() throws Exception {
        return requestSecurityTokenResponse(null);
    }

    public String requestSecurityTokenResponse(String appliesTo) throws Exception {
        String action = null;
        if (isSecureConv) {
            action = namespace + "/RST/SCT";
        }
        return requestSecurityTokenResponse(appliesTo, action, "/Issue", null);
    }

    public String requestSecurityTokenResponse(String appliesTo, String action,
            String requestType, SecurityToken target) throws Exception {
        createClient();
        BindingOperationInfo boi = findOperation("/RST/Issue");

        client.getRequestContext().putAll(ctx);
        if (action != null) {
            client.getRequestContext().put(SoapBindingConstants.SOAP_ACTION,
                    action);
        } else {
            client.getRequestContext().put(SoapBindingConstants.SOAP_ACTION,
                    namespace + "/RST/Issue");
        }

        W3CDOMStreamWriter writer = new W3CDOMStreamWriter();
        writer.writeStartElement("wst", "RequestSecurityToken", namespace);
        writer.writeNamespace("wst", namespace);
        if (context != null) {
            writer.writeAttribute(null, "Context", context);
        }

        boolean wroteKeySize = false;
        String keyTypeTemplate = null;
        String sptt = null;

        if (template != null) {
            if (this.useSecondaryParameters()) {
                writer.writeStartElement("wst", "SecondaryParameters",
                        namespace);
            }

            Element tl = DOMUtils.getFirstElement(template);
            while (tl != null) {
                StaxUtils.copy(tl, writer);
                if ("KeyType".equals(tl.getLocalName())) {
                    keyTypeTemplate = DOMUtils.getContent(tl);
                } else if ("KeySize".equals(tl.getLocalName())) {
                    wroteKeySize = true;
                    keySize = Integer.parseInt(DOMUtils.getContent(tl));
                } else if ("TokenType".equals(tl.getLocalName())) {
                    sptt = DOMUtils.getContent(tl);
                }
                tl = DOMUtils.getNextElement(tl);
            }

            if (this.useSecondaryParameters()) {
                writer.writeEndElement();
            }
        }

        addRequestType(requestType, writer);
        if (enableAppliesTo) {
            addAppliesTo(writer, appliesTo);
        }

        addClaims(writer);

        Element onBehalfOfToken = getOnBehalfOfToken();
        if (onBehalfOfToken != null) {
            writer.writeStartElement("wst", "OnBehalfOf", namespace);
            StaxUtils.copy(onBehalfOfToken, writer);
            writer.writeEndElement();
        }
        if (sptt == null) {
            addTokenType(writer);
        }
        if (isSecureConv || enableLifetime) {
            addLifetime(writer);
        }
        if (keyTypeTemplate == null) {
            keyTypeTemplate = writeKeyType(writer, keyType);
        }

        byte[] requestorEntropy = null;
        X509Certificate cert = null;
        Crypto crypto = null;

        if (keySize <= 0) {
            keySize = 256;
        }
        if (keyTypeTemplate != null && keyTypeTemplate.endsWith("SymmetricKey")) {
            requestorEntropy = writeElementsForRSTSymmetricKey(writer,
                    wroteKeySize);
        } else if (keyTypeTemplate != null
                && keyTypeTemplate.endsWith("PublicKey")) {
            crypto = createCrypto(false);
            cert = getCert(crypto);
            writeElementsForRSTPublicKey(writer, cert);
        }

        if (target != null) {
            writer.writeStartElement("wst", "RenewTarget", namespace);
            Element el = target.getUnattachedReference();
            if (el == null) {
                el = target.getAttachedReference();
            }
            StaxUtils.copy(el, writer);
            writer.writeEndElement();
        }

        Element actAsSecurityToken = getActAsToken();
        if (actAsSecurityToken != null) {
            writer.writeStartElement(STSUtils.WST_NS_08_02, "ActAs");
            StaxUtils.copy(actAsSecurityToken, writer);
            writer.writeEndElement();
        }

        writer.writeEndElement();

        Object obj[] = client.invoke(boi, new DOMSource(writer.getDocument()
                .getDocumentElement()));

        DOMSource rstr = (DOMSource) obj[0];

        StringWriter sw = new StringWriter();
        try {
            Transformer t = TransformerFactory.newInstance().newTransformer();
            t.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            t.transform(rstr, new StreamResult(sw));
        } catch (TransformerException te) {
            LOG.warn("nodeToString Transformer Exception");
        }
        return sw.toString();

    }

}
