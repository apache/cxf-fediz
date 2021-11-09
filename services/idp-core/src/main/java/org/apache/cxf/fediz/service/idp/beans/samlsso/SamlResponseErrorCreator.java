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

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.exception.ProcessingException.TYPE;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.samlsso.SAML2PResponseComponentBuilder;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
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
public class SamlResponseErrorCreator extends AbstractSamlResponseCreator {

    private static final Logger LOG = LoggerFactory.getLogger(SamlResponseErrorCreator.class);

    public String createSAMLResponse(RequestContext context, boolean logout, boolean requestor,
                                     Idp idp, String requestID, String destination) throws ProcessingException {
        Document doc = DOMUtils.newDocument();

        String statusValue = "urn:oasis:names:tc:SAML:2.0:status:Responder";
        if (requestor) {
            statusValue = "urn:oasis:names:tc:SAML:2.0:status:Requester";
        }

        Status status =
            SAML2PResponseComponentBuilder.createStatus(statusValue, null);
        final Element responseElement;
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

}
