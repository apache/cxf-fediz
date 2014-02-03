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

import java.util.Collections;
import java.util.List;

import org.apache.cxf.sts.request.ReceivedToken;
import org.apache.cxf.sts.token.delegation.TokenDelegationParameters;
import org.apache.cxf.sts.token.delegation.TokenDelegationResponse;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;

/**
 * The SAML TokenDelegationHandler implementation. It disallows ActAs or OnBehalfOf for
 * all cases apart from the case of a Bearer SAML Token. It differs from the SAMLDelegationHandler
 * in the STS core, in that it doesn't require that the AppliesTo address match an 
 * AudienceRestriction address in the token.
 */
public class FedizSAMLDelegationHandler 
    extends org.apache.cxf.sts.token.delegation.SAMLDelegationHandler {
    
    @Override
    public boolean canHandleToken(ReceivedToken delegateTarget) {
        return super.canHandleToken(delegateTarget);
    }
    @Override
    public TokenDelegationResponse isDelegationAllowed(TokenDelegationParameters tokenParameters) { 
        return super.isDelegationAllowed(tokenParameters);
    }
    @Override
    protected List<String> getAudienceRestrictions(SamlAssertionWrapper assertion) {
        return Collections.emptyList();
    }
    
}
