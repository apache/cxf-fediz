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
package org.apache.cxf.fediz.service.idp.beans;

import org.apache.cxf.fediz.service.idp.STSUserDetails;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.util.WebUtils;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.webflow.execution.RequestContext;

/**
 * This class is responsible to cache IDP token.
 */
@Component
public class CacheTokenForWauthAction {

    private static final String IDP_CONFIG = "idpConfig";
    private static final Logger LOG = LoggerFactory.getLogger(CacheTokenForWauthAction.class);


    public void submit(RequestContext context) {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Assert.isInstanceOf(STSUserDetails.class, auth.getDetails());
        final STSUserDetails stsUserDetails = (STSUserDetails) auth.getDetails();
        SecurityToken securityToken = stsUserDetails.getSecurityToken();

        Idp idpConfig = (Idp)WebUtils.getAttributeFromFlowScope(context, IDP_CONFIG);

        WebUtils.putAttributeInExternalContext(context, idpConfig.getRealm(), securityToken);
        LOG.info("Token [IDP_TOKEN=" + securityToken.getId()
                + "] for realm ["
                + idpConfig.getRealm() + "] successfully cached.");
    }
}
