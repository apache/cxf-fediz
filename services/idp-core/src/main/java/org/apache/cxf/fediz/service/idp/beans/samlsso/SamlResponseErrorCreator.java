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
package org.apache.cxf.fediz.service.idp.beans.samlsso;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.cxf.common.util.Base64Utility;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.exception.ProcessingException.TYPE;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.samlsso.SAML2PResponseComponentBuilder;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.rs.security.saml.DeflateEncoderDecoder;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.apache.wss4j.common.util.DOM2Writer;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.RequestContext;

/**
 * Create a SAML Error Response
 */
@Component
public class SamlResponseErrorCreator {

    private static final Logger LOG = LoggerFactory.getLogger(SamlResponseErrorCreator.class);
    private boolean supportDeflateEncoding;
    private boolean useRealmForIssuer;

    public String createSAMLResponse(RequestContext context, boolean logout, boolean requestor,
                                     Idp idp, String requestID, String destination) throws ProcessingException {
        Document doc = DOMUtils.newDocument();

        String statusValue = "urn:oasis:names:tc:SAML:2.0:status:Responder";
        if (requestor) {
            statusValue = "urn:oasis:names:tc:SAML:2.0:status:Requester";
        }

        Status status =
            SAML2PResponseComponentBuilder.createStatus(statusValue, null);
        Element responseElement = null;
        try {
            if (logout) {
                responseElement = createLogoutResponse(idp, statusValue, destination, requestID);
            } else {
                Response response =
                    SAML2PResponseComponentBuilder.createSAMLResponse(requestID, idp.getRealm(), status);
                Element policyElement = OpenSAMLUtil.toDom(response, doc);
                doc.appendChild(policyElement);

                responseElement = policyElement;
            }

            return encodeResponse(responseElement);
        } catch (Exception e) {
            LOG.warn("Error marshalling SAML Token: {}", e.getMessage());
            throw new ProcessingException(TYPE.BAD_REQUEST);
        }
    }

    protected Element createLogoutResponse(Idp idp, String statusValue,
                                           String destination, String requestID) throws Exception {
        Document doc = DOMUtils.newDocument();

        Status status =
            SAML2PResponseComponentBuilder.createStatus(statusValue, null);
        String issuer = useRealmForIssuer ? idp.getRealm() : idp.getIdpUrl().toString();
        LogoutResponse response =
            SAML2PResponseComponentBuilder.createSAMLLogoutResponse(requestID, issuer, status, destination);

        Element policyElement = OpenSAMLUtil.toDom(response, doc);
        doc.appendChild(policyElement);

        return policyElement;
    }

    protected String encodeResponse(Element response) throws IOException {
        String responseMessage = DOM2Writer.nodeToString(response);
        LOG.debug("Created Response: {}", responseMessage);

        if (supportDeflateEncoding) {
            DeflateEncoderDecoder encoder = new DeflateEncoderDecoder();
            byte[] deflatedBytes = encoder.deflateToken(responseMessage.getBytes(StandardCharsets.UTF_8));

            return Base64Utility.encode(deflatedBytes);
        }

        return Base64Utility.encode(responseMessage.getBytes());
    }

    public boolean isSupportDeflateEncoding() {
        return supportDeflateEncoding;
    }

    public void setSupportDeflateEncoding(boolean supportDeflateEncoding) {
        this.supportDeflateEncoding = supportDeflateEncoding;
    }

    public boolean isUseRealmForIssuer() {
        return useRealmForIssuer;
    }

    public void setUseRealmForIssuer(boolean useRealmForIssuer) {
        this.useRealmForIssuer = useRealmForIssuer;
    }
}
