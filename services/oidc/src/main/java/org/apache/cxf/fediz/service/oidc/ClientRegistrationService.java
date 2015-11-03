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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.SecurityContext;

import org.apache.cxf.common.util.Base64UrlUtility;
import org.apache.cxf.rs.security.oauth2.client.Consumer;
import org.apache.cxf.rs.security.oauth2.client.Consumers;
import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rt.security.crypto.CryptoUtils;

@Path("/")
public class ClientRegistrationService {
    
    private Map<String, Map<String, Consumer>> registrations = 
            new ConcurrentHashMap<String, Map<String, Consumer>>();
    private OAuthDataManager manager;    
    @Context
    private SecurityContext sc;
    
    @GET
    @Produces(MediaType.TEXT_HTML)
    @Path("/")
    public RegisterClient registerStart() {
        return new RegisterClient();
    }
    
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    @Path("/register")
    public Consumers registerForm(@FormParam("appName") String appName,
                                 @FormParam("appDescription") String appDesc,
                                 @FormParam("appType") String appType,
                                 @FormParam("redirectURI") String redirectURI) {
        String clientId = generateClientId();
        //String clientSecret = 
        //    "confidential".equals(appType) ? generateClientSecret() : null;
        String clientSecret = generateClientSecret();
    
        Client newClient = new Client(clientId, clientSecret, true, appName, null);
        newClient.setApplicationDescription(appDesc);
        newClient.setRedirectUris(Collections.singletonList(redirectURI));
        
        return registerNewClient(newClient);
    }
    
    protected String generateClientId() {
        return Base64UrlUtility.encode(CryptoUtils.generateSecureRandomBytes(10));
    }
    
    protected String generateClientSecret() {
        return Base64UrlUtility.encode(CryptoUtils.generateSecureRandomBytes(15));
    }
    
    private Consumers registerNewClient(Client newClient) {
        manager.registerClient(newClient);
        String userName = sc.getUserPrincipal().getName();
        Map<String, Consumer> userClientRegs = registrations.get(userName);
        if (userClientRegs == null) {
            userClientRegs = new HashMap<String, Consumer>();
            registrations.put(userName, userClientRegs);
        }
        Consumer c = new Consumer(newClient.getClientId(), newClient.getClientSecret());
        c.setDescription(newClient.getApplicationDescription());
        userClientRegs.put(newClient.getClientId(), c);
        return new Consumers(new HashSet<Consumer>(userClientRegs.values()));
        
    }
    
    public void setDataProvider(OAuthDataManager m) {
        this.manager = m;
    }
}

