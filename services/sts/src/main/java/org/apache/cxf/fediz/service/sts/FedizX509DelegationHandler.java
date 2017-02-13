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
package org.apache.cxf.fediz.service.sts;

import org.w3c.dom.Element;
import org.apache.cxf.sts.request.ReceivedToken;
import org.apache.cxf.sts.request.ReceivedToken.STATE;
import org.apache.cxf.sts.token.delegation.TokenDelegationHandler;
import org.apache.cxf.sts.token.delegation.TokenDelegationParameters;
import org.apache.cxf.sts.token.delegation.TokenDelegationResponse;
import org.apache.wss4j.dom.WSConstants;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A delegation handler to allow X.509 Certificates.
 */
public class FedizX509DelegationHandler implements TokenDelegationHandler {

    private static final Logger LOG = LoggerFactory.getLogger(FedizX509DelegationHandler.class);

    public boolean canHandleToken(ReceivedToken delegateTarget) {
        Object token = delegateTarget.getToken();
        if (token instanceof Element) {
            Element tokenElement = (Element)token;
            String namespace = tokenElement.getNamespaceURI();
            String localname = tokenElement.getLocalName();
            if (WSConstants.SIG_NS.equals(namespace) && WSConstants.X509_DATA_LN.equals(localname)) {
                return true;
            }
        }
        return false;
    }

    public TokenDelegationResponse isDelegationAllowed(TokenDelegationParameters tokenParameters) {
        TokenDelegationResponse response = new TokenDelegationResponse();
        ReceivedToken delegateTarget = tokenParameters.getToken();
        response.setToken(delegateTarget);

        if (!delegateTarget.isDOMElement()) {
            return response;
        }

        if (delegateTarget.getState() == STATE.VALID && delegateTarget.getPrincipal() != null) {
            response.setDelegationAllowed(true);
            LOG.debug("Delegation is allowed for: " + delegateTarget.getPrincipal());
        } else {
            LOG.debug("Delegation is not allowed, as the token is invalid or the principal is null");
        }

        return response;
    }

}
