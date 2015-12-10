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

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
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
import org.apache.cxf.common.util.StringUtils;
import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.common.UserSubject;
import org.apache.cxf.rt.security.crypto.CryptoUtils;

@Path("/")
public class ClientRegistrationService {

    private Map<String, Collection<Client>> registrations = new ConcurrentHashMap<String, Collection<Client>>();
    private OAuthDataManager manager;
    private Map<String, String> homeRealms = new LinkedHashMap<String, String>();
    private boolean protectIdTokenWithClientSecret;

    @Context
    private SecurityContext sc;

    @GET
    @Produces(MediaType.TEXT_HTML)
    @Path("/register")
    public RegisterClient registerStart() {
        return new RegisterClient(homeRealms);
    }

    @GET
    @Produces(MediaType.TEXT_HTML)
    @Path("/")
    public Collection<Client> getClients() {
        return getClientRegistrations();
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    @Path("/")
    public Collection<Client> registerForm(@FormParam("appName") String appName,
        @FormParam("appDescription") String appDesc, @FormParam("appType") String appType,
        @FormParam("redirectURI") String redirectURI, @FormParam("homeRealm") String homeRealm) {
        String clientId = generateClientId();
        boolean isConfidential = "confidential".equals(appType);
        String clientSecret = isConfidential
            ? generateClientSecret()
            : null;

        FedizClient newClient = new FedizClient(clientId, clientSecret, isConfidential, appName);
        newClient.setHomeRealm(homeRealm);
        newClient.setApplicationDescription(appDesc);
        if (!StringUtils.isEmpty(redirectURI)) {
            newClient.setRedirectUris(Collections.singletonList(redirectURI));
        }
        String userName = sc.getUserPrincipal().getName();
        UserSubject userSubject = new UserSubject(userName);
        newClient.setResourceOwnerSubject(userSubject);

        return registerNewClient(newClient);
    }

    protected String generateClientId() {
        return Base64UrlUtility.encode(CryptoUtils.generateSecureRandomBytes(10));
    }

    protected String generateClientSecret() {
        // TODO: may need to be 384/8 or 512/8 if not a default HS256 but HS384 or HS512
        int keySizeOctets = protectIdTokenWithClientSecret
            ? 32
            : 16;
        return Base64UrlUtility.encode(CryptoUtils.generateSecureRandomBytes(keySizeOctets));
    }

    protected Collection<Client> registerNewClient(Client newClient) {
        manager.setClient(newClient);
        Collection<Client> clientRegistrations = getClientRegistrations();
        clientRegistrations.add(newClient);
        return clientRegistrations;
    }

    protected Collection<Client> getClientRegistrations() {
        String userName = getUserName();
        return getClientRegistrations(userName);
    }

    protected Collection<Client> getClientRegistrations(String userName) {
        Collection<Client> userClientRegs = registrations.get(userName);
        if (userClientRegs == null) {
            userClientRegs = new HashSet<Client>();
            registrations.put(userName, userClientRegs);
        }
        return userClientRegs;
    }

    private String getUserName() {
        if (sc == null || sc.getUserPrincipal() == null) {
            return null;
        }
        return sc.getUserPrincipal().getName();
    }

    public void setDataProvider(OAuthDataManager m) {
        this.manager = m;
    }

    public void setHomeRealms(Map<String, String> homeRealms) {
        this.homeRealms = homeRealms;
    }

    public void init() {
        for (Client c : manager.getClients()) {
            String userName = c.getResourceOwnerSubject().getLogin();
            getClientRegistrations(userName).add(c);
        }
    }

    public void setProtectIdTokenWithClientSecret(boolean protectIdTokenWithClientSecret) {
        this.protectIdTokenWithClientSecret = protectIdTokenWithClientSecret;
    }
}
