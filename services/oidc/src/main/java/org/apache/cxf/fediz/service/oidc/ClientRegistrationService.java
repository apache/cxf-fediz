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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.SecurityContext;

import org.apache.commons.validator.routines.UrlValidator;
import org.apache.cxf.common.util.Base64UrlUtility;
import org.apache.cxf.common.util.StringUtils;
import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.common.UserSubject;
import org.apache.cxf.rs.security.oauth2.grants.code.AuthorizationCodeDataProvider;
import org.apache.cxf.rs.security.oauth2.provider.ClientRegistrationProvider;
import org.apache.cxf.rs.security.oauth2.provider.OAuthDataProvider;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;
import org.apache.cxf.rt.security.crypto.CryptoUtils;

@Path("/")
public class ClientRegistrationService {

    private Map<String, Collection<Client>> registrations = new ConcurrentHashMap<String, Collection<Client>>();
    private OAuthDataProvider dataProvider;
    private ClientRegistrationProvider clientProvider;
    private Map<String, String> homeRealms = new LinkedHashMap<String, String>();
    private boolean protectIdTokenWithClientSecret;
    private Map<String, String> clientScopes;
    
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

    @GET
    @Produces(MediaType.TEXT_HTML)
    @Path("/{id}")
    public Client getRegisteredClient(@PathParam("id") String id) {
        for (Client c : getClientRegistrations()) {
            if (c.getClientId().equals(id)) {
                return c;
            }
        }
        return null;
    }
    
    
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    @Path("/{id}/remove")
    public Collection<Client> removeClient(@PathParam("id") String id) {
        Collection<Client> clients = getClientRegistrations(); 
        for (Iterator<Client> it = clients.iterator(); it.hasNext();) {
            Client c = it.next();
            if (c.getClientId().equals(id)) {
                clientProvider.removeClient(id);
                it.remove();
                break;
            }
        }
        return clients;
    }
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    @Path("/{id}/reset")
    public Client resetClient(@PathParam("id") String id) {
        Client c = getRegisteredClient(id);
        if (c.isConfidential()) {
            c.setClientSecret(generateClientSecret());
        }
        clientProvider.setClient(c);
        return c;
    }
    
    @GET
    @Produces(MediaType.TEXT_HTML)
    @Path("/{id}/tokens")
    public ClientTokens getClientIssuedTokens(@PathParam("id") String id) {
        Client c = getRegisteredClient(id);
        return doGetClientIssuedTokens(c);
    }
    
    protected ClientTokens doGetClientIssuedTokens(Client c) {
        // Right now the user who is registering the clients 
        // is the one who is working with them, i.e, client registrations 
        // are user specific, so passing null is OK
        return new ClientTokens(c, 
                                dataProvider.getAccessTokens(c, null),
                                dataProvider.getRefreshTokens(c, null));
    }
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    @Path("/{id}/at/{tokenId}/revoke")
    public ClientTokens revokeClientAccessToken(@PathParam("id") String clientId,
                                                      @PathParam("tokenId") String tokenId) {
        return doRevokeClientToken(clientId, tokenId, OAuthConstants.ACCESS_TOKEN);
    }
    
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    @Path("/{id}/rt/{tokenId}/revoke")
    public ClientTokens revokeClientRefreshToken(@PathParam("id") String clientId,
                                                      @PathParam("tokenId") String tokenId) {
        return doRevokeClientToken(clientId, tokenId, OAuthConstants.REFRESH_TOKEN);
    }
    
    protected ClientTokens doRevokeClientToken(String clientId,
                                                     String tokenId,
                                                     String tokenType) {
        Client c = getRegisteredClient(clientId);
        dataProvider.revokeToken(c, tokenId, tokenType);
        return doGetClientIssuedTokens(c);
    }
    
    @GET
    @Produces(MediaType.TEXT_HTML)
    @Path("/{id}/codes")
    public ClientCodeGrants getClientCodeGrants(@PathParam("id") String id) {
        if (dataProvider instanceof AuthorizationCodeDataProvider) {
            Client c = getRegisteredClient(id);
            return new ClientCodeGrants(c, 
                    ((AuthorizationCodeDataProvider)dataProvider).getCodeGrants(c, null));
        }
        return null;
    }
    
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    @Path("/{id}/codes/{code}/revoke")
    public ClientCodeGrants revokeClientCodeGrant(@PathParam("id") String id,
                                                  @PathParam("code") String code) {
        if (dataProvider instanceof AuthorizationCodeDataProvider) {
            ((AuthorizationCodeDataProvider)dataProvider).removeCodeGrant(code);
            return getClientCodeGrants(id);
        }
        return null;
    }
    
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    @Path("/")
    public Collection<Client> registerForm(@FormParam("client_name") String appName,
                                           @FormParam("client_type") String appType, 
                                           @FormParam("client_audience") String audience,
                                           @FormParam("client_redirectURI") String redirectURI,
                                           @FormParam("client_homeRealm") String homeRealm
    ) throws InvalidRegistrationException {
        
        // Check parameters
        if (appName == null || "".equals(appName)) {
            throw new InvalidRegistrationException("The client id must not be empty");
        }
        if (appType == null) {
            throw new InvalidRegistrationException("The client type must not be empty");
        }
        if (!("confidential".equals(appType) || "public".equals(appType))) {
            throw new InvalidRegistrationException("An invalid client type was specified: " + appType);
        }
        //TODO: support multiple redirect URIs
        if (redirectURI != null && !"".equals(redirectURI) && !isValidURI(redirectURI, false)) {
            throw new InvalidRegistrationException("An invalid redirect URI was specified: " + redirectURI);
        }
        
        String clientId = generateClientId();
        boolean isConfidential = "confidential".equals(appType);
        String clientSecret = isConfidential
            ? generateClientSecret()
            : null;

        FedizClient newClient = new FedizClient(clientId, clientSecret, isConfidential, appName);
        newClient.setHomeRealm(homeRealm);
        if (!StringUtils.isEmpty(redirectURI)) {
            newClient.setRedirectUris(Collections.singletonList(redirectURI));
        }
        String userName = sc.getUserPrincipal().getName();
        UserSubject userSubject = new UserSubject(userName);
        newClient.setResourceOwnerSubject(userSubject);

        newClient.setRegisteredAt(System.currentTimeMillis() / 1000);
        
        if (clientScopes != null && !clientScopes.isEmpty()) {
            newClient.setRegisteredScopes(new ArrayList<String>(clientScopes.keySet()));
        }
        
        if (!StringUtils.isEmpty(audience)) {
            String[] auds = audience.trim().split(" ");
            List<String> registeredAuds = new LinkedList<String>();
            for (String aud : auds) {
                // make sure it is a proper URI
                if (!"".equals(aud) && !isValidURI(aud, true)) {
                    throw new InvalidRegistrationException("An invalid audience URI was specified: " + aud);
                }
                registeredAuds.add(aud);
            }
            if (!registeredAuds.isEmpty()) {
                newClient.setRegisteredAudiences(registeredAuds);
            }
        }
        
        return registerNewClient(newClient);
    }
    
    private boolean isValidURI(String uri, boolean requireHttps) {
        
        UrlValidator urlValidator = null;
        
        if (requireHttps) {
            String[] schemes = {"https"};
            urlValidator = new UrlValidator(schemes, UrlValidator.ALLOW_LOCAL_URLS);
        } else {
            urlValidator = new UrlValidator(UrlValidator.ALLOW_LOCAL_URLS
                                                     + UrlValidator.ALLOW_ALL_SCHEMES);
        }
        
        if (!urlValidator.isValid(uri)) {
            return false;
        }
        
        // Do additional checks on the URI
        try {
            URI parsedURI = new URI(uri);
            // The URI can't have a fragment according to the OAuth 2.0 spec (+ audience spec)
            if (parsedURI.getFragment() != null) {
                return false;
            }
        } catch (URISyntaxException ex) {
            return false;
        }
        
        return true;
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
        clientProvider.setClient(newClient);
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

    public void setHomeRealms(Map<String, String> homeRealms) {
        this.homeRealms = homeRealms;
    }

    public void init() {
        for (Client c : clientProvider.getClients(null)) {
            String userName = c.getResourceOwnerSubject().getLogin();
            getClientRegistrations(userName).add(c);
        }
    }

    public void setProtectIdTokenWithClientSecret(boolean protectIdTokenWithClientSecret) {
        this.protectIdTokenWithClientSecret = protectIdTokenWithClientSecret;
    }

    public void setClientScopes(Map<String, String> clientScopes) {
        this.clientScopes = clientScopes;
    }

    public OAuthDataProvider getDataProvider() {
        return dataProvider;
    }

    public void setDataProvider(OAuthDataProvider dataProvider) {
        this.dataProvider = dataProvider;
    }

    public void setClientProvider(ClientRegistrationProvider clientProvider) {
        this.clientProvider = clientProvider;
    }
}
