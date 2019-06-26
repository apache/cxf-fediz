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

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.util.WebUtils;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.RequestContext;

/**
 * Parse the parameters to create the URL for local redirection
 */
@Component
public class LocalRedirectCreator {

    public String createRedirectURL(RequestContext context, Idp idp) throws UnsupportedEncodingException {
        StringBuilder redirectURL = new StringBuilder(25);
        redirectURL.append(idp.getIdpUrl().toString()).append('?');

        String relayState = (String)WebUtils.getAttributeFromFlowScope(context, "RelayState");
        redirectURL.append("RelayState=").append(relayState).append('&');
        String samlRequest = (String)WebUtils.getAttributeFromFlowScope(context, "SAMLRequest");
        redirectURL.append("SAMLRequest=").append(URLEncoder.encode(samlRequest, "UTF-8"));

        String signature = (String)WebUtils.getAttributeFromFlowScope(context, "Signature");
        if (signature != null) {
            redirectURL.append('&');
            redirectURL.append("Signature=").append(URLEncoder.encode(signature, "UTF-8"));
        }

        return redirectURL.toString();
    }


}
