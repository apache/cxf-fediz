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
package org.apache.cxf.fediz.service.oidc;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.grants.code.JCacheCodeDataProvider;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;
import org.apache.cxf.rs.security.oidc.utils.OidcUtils;

public class OAuthDataProviderImpl extends JCacheCodeDataProvider {
    private static final Set<String> NON_REDIRECTION_FLOWS = 
        new HashSet<>(Arrays.asList(OAuthConstants.CLIENT_CREDENTIALS_GRANT, 
                                    OAuthConstants.RESOURCE_OWNER_GRANT));

    @Override
    protected void checkRequestedScopes(Client client, List<String> requestedScopes) {
        String grantType = super.getCurrentRequestedGrantType();
        if (grantType != null && !NON_REDIRECTION_FLOWS.contains(grantType)    
            && !requestedScopes.contains(OidcUtils.OPENID_SCOPE)) {
            throw new OAuthServiceException("Required scopes are missing");
        }
    }

}
