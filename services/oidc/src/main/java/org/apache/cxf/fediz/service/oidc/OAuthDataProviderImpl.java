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

import java.util.List;

import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.common.OAuthPermission;
import org.apache.cxf.rs.security.oauth2.grants.code.DefaultEHCacheCodeDataProvider;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;
import org.apache.cxf.rs.security.oidc.utils.OidcUtils;

public class OAuthDataProviderImpl extends DefaultEHCacheCodeDataProvider {

    @Override
    public List<OAuthPermission> convertScopeToPermissions(Client client, List<String> requestedScopes) {
        //TODO: push this code into the abstract class
        //NOTE: if OIDC-registered clients will be allowed to support not only code/implicit
        // (as it is now) but also client credentials/etc then the check below will need to be more strict
        // with the help of getMessageContext().get(OAuthConstants.GRANT_TYPE)
        if (!client.getAllowedGrantTypes().contains(OAuthConstants.CLIENT_CREDENTIALS_GRANT)
            && !client.getAllowedGrantTypes().contains(OAuthConstants.RESOURCE_OWNER_GRANT)    
            && !requestedScopes.contains(OidcUtils.OPENID_SCOPE)) {
            throw new OAuthServiceException("Required scopes are missing");
        }
        return super.convertScopeToPermissions(client, requestedScopes);
    }
}
