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

import java.util.Collections;
import java.util.List;

import javax.ws.rs.core.MultivaluedMap;

import org.apache.cxf.jaxrs.ext.MessageContext;
import org.apache.cxf.rs.security.oauth2.common.AccessTokenValidation;
import org.apache.cxf.rs.security.oauth2.common.ServerAccessToken;
import org.apache.cxf.rs.security.oauth2.provider.AccessTokenValidator;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;

public class FedizAccessTokenValidator implements AccessTokenValidator {

    private OAuthDataManager dataProvider;
    
    @Override
    public List<String> getSupportedAuthorizationSchemes() {
        return Collections.singletonList(OAuthConstants.BEARER_AUTHORIZATION_SCHEME);
    }

    @Override
    public AccessTokenValidation validateAccessToken(MessageContext mc, String authScheme, String authSchemeData,
            MultivaluedMap<String, String> extraProps) throws OAuthServiceException {
        
        // This is the access token used by a 3rd party client when accessing a REST service 
        ServerAccessToken token = dataProvider.getAccessToken(authSchemeData);
        
        String idToken = token.getSubject().getProperties().get("id_token");
        if (idToken != null) {
            //TODO: validate the user behind this id_token is still a valid user ?
        }
        // Do some Fediz specific token validation ? 
        // and
        // Let CXF do the core validation (is access token still valid, etc)
        return new AccessTokenValidation(token);
    }

    public void setDataProvider(OAuthDataManager dataProvider) {
        this.dataProvider = dataProvider;
    }

}
