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

package org.apache.cxf.fediz.service.oidc.clients;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;

import org.apache.commons.text.StringEscapeUtils;
import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.DomainValidator.ArrayType;
import org.apache.commons.validator.routines.UrlValidator;
import org.apache.cxf.common.logging.LogUtils;
import org.apache.cxf.common.util.Base64UrlUtility;
import org.apache.cxf.common.util.StringUtils;
import org.apache.cxf.fediz.service.oidc.CSRFUtils;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.apache.cxf.jaxrs.utils.ExceptionUtils;
import org.apache.cxf.rs.security.oauth2.common.AccessToken;
import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.common.ServerAccessToken;
import org.apache.cxf.rs.security.oauth2.common.UserSubject;
import org.apache.cxf.rs.security.oauth2.grants.code.AuthorizationCodeDataProvider;
import org.apache.cxf.rs.security.oauth2.grants.code.ServerAuthorizationCodeGrant;
import org.apache.cxf.rs.security.oauth2.provider.ClientRegistrationProvider;
import org.apache.cxf.rs.security.oauth2.provider.OAuthDataProvider;
import org.apache.cxf.rs.security.oauth2.tokens.refresh.RefreshToken;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;
import org.apache.cxf.rs.security.oidc.idp.OidcUserSubject;
import org.apache.cxf.rt.security.crypto.CryptoUtils;

@Path("/")
public class ClientRegistrationService {

    private static final Logger LOG = LogUtils.getL7dLogger(ClientRegistrationService.class);

    private final Map<String, Collection<Client>> registrations = new HashMap<>();
    private OAuthDataProvider dataProvider;
    private ClientRegistrationProvider clientProvider;
    private Map<String, String> homeRealms = Collections.emptyMap();
    private boolean protectIdTokenWithClientSecret;
    private Map<String, String> clientScopes;

    private MessageContext mc;
    private String userRole;

    @Context
    public void setMessageContext(MessageContext messageContext) {
        this.mc = messageContext;
    }

    @GET
    @Produces(MediaType.TEXT_HTML)
    @Path("/register")
    public RegisterClient registerStart() {
        checkSecurityContext();
        return new RegisterClient(homeRealms);
    }

    @GET
    @Produces(MediaType.TEXT_HTML)
    @Path("/")
    public RegisteredClients getClients() {
        checkSecurityContext();
        return new RegisteredClients(getClientRegistrations());
    }

    @GET
    @Produces(MediaType.TEXT_HTML)
    @Path("/{id}")
    public Client getRegisteredClient(@PathParam("id") String id) {
        checkSecurityContext();
        for (Client c : getClientRegistrations()) {
            if (c.getClientId().equals(id)) {
                return c;
            }
        }
        return null;
    }

    @GET
    @Produces(MediaType.TEXT_HTML)
    @Path("/{id}/edit")
    public EditClient editClient(@PathParam("id") String id) {
        checkSecurityContext();
        for (Client c : getClientRegistrations()) {
            if (c.getClientId().equals(id)) {
                return new EditClient(c, homeRealms);
            }
        }
        return null;
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    @Path("/{id}/remove")
    public RegisteredClients removeClient(@PathParam("id") String id,
                                          @FormParam("client_csrfToken") String csrfToken) {
        // CSRF
        checkCSRFToken(csrfToken);
        checkSecurityContext();
        
        Collection<Client> clients = getClientRegistrations();
        for (Iterator<Client> it = clients.iterator(); it.hasNext();) {
            Client c = it.next();
            if (c.getClientId().equals(id)) {
                clientProvider.removeClient(id);
                it.remove();
                break;
            }
        }
        return new RegisteredClients(clients);
    }
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    @Path("/{id}/reset")
    public Client resetClient(@PathParam("id") String id,
                              @FormParam("client_csrfToken") String csrfToken) {
        // CSRF
        checkCSRFToken(csrfToken);
        checkSecurityContext();

        Client c = getRegisteredClient(id);
        if (c == null) {
            throw new InvalidRegistrationException("The client id is invalid");
        }
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
        checkSecurityContext();
        Client c = getRegisteredClient(id);
        if (c == null) {
            throw new InvalidRegistrationException("The client id is invalid");
        }
        return doGetClientIssuedTokens(c);
    }

    protected ClientTokens doGetClientIssuedTokens(Client c) {
        Comparator<AccessToken> tokenComp = Comparator.comparingLong(AccessToken::getIssuedAt);
        UserSubject subject = new OidcUserSubject(getUserName());
        Collection<ServerAccessToken> accessTokens = new TreeSet<>(tokenComp);
        accessTokens.addAll(dataProvider.getAccessTokens(c, subject));
        Collection<RefreshToken> refreshTokens = new TreeSet<>(tokenComp);
        refreshTokens.addAll(dataProvider.getRefreshTokens(c, subject));
        return new ClientTokens(c, accessTokens, refreshTokens);
    }
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    @Path("/{id}/at/{tokenId}/revoke")
    public ClientTokens revokeClientAccessToken(@PathParam("id") String clientId,
                                                      @PathParam("tokenId") String tokenId,
                                                      @FormParam("client_csrfToken") String csrfToken) {
        
        return doRevokeClientToken(clientId, csrfToken, tokenId, OAuthConstants.ACCESS_TOKEN);
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    @Path("/{id}/rt/{tokenId}/revoke")
    public ClientTokens revokeClientRefreshToken(@PathParam("id") String clientId,
                                                      @PathParam("tokenId") String tokenId,
                                                      @FormParam("client_csrfToken") String csrfToken) {
        return doRevokeClientToken(clientId, csrfToken, tokenId, OAuthConstants.REFRESH_TOKEN);
    }

    protected ClientTokens doRevokeClientToken(String clientId,
                                               String csrfToken,
                                               String tokenId,
                                               String tokenType) {
        // CSRF
        checkCSRFToken(csrfToken);
        checkSecurityContext();

        Client c = getRegisteredClient(clientId);
        if (c == null) {
            throw new InvalidRegistrationException("The client id is invalid");
        }
        dataProvider.revokeToken(c, tokenId, tokenType);
        return doGetClientIssuedTokens(c);
    }

    @GET
    @Produces(MediaType.TEXT_HTML)
    @Path("/{id}/codes")
    public ClientCodeGrants getClientCodeGrants(@PathParam("id") String id) {
        checkSecurityContext();
        if (dataProvider instanceof AuthorizationCodeDataProvider) {
            Client c = getRegisteredClient(id);
            if (c == null) {
                throw new InvalidRegistrationException("The client id is invalid");
            }
            UserSubject subject = new OidcUserSubject(getUserName());
            Collection<ServerAuthorizationCodeGrant> codeGrants = new TreeSet<>(
                Comparator.comparingLong(ServerAuthorizationCodeGrant::getIssuedAt));
            codeGrants.addAll(((AuthorizationCodeDataProvider)dataProvider).getCodeGrants(c, subject));
            return new ClientCodeGrants(c, codeGrants);
        }
        return null;
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    @Path("/{id}/codes/{code}/revoke")
    public ClientCodeGrants revokeClientCodeGrant(@PathParam("id") String id,
                                                  @PathParam("code") String code,
                                                  @FormParam("client_csrfToken") String csrfToken) {
        // CSRF
        checkCSRFToken(csrfToken);
        checkSecurityContext();

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
    public Response registerForm(@FormParam("client_name") String appName,
                                 @FormParam("client_type") String appType,
                                 @FormParam("client_audience") String audience,
                                 @FormParam("client_redirectURI") String redirectURI,
                                 @FormParam("client_logoutURI") String logoutURI,
                                 @FormParam("client_homeRealm") String homeRealm,
                                 @FormParam("client_csrfToken") String csrfToken
    ) {
        try {
            // CSRF
            checkCSRFToken(csrfToken);
            checkSecurityContext();

            // Client Name
            if (StringUtils.isEmpty(appName)) {
                throw new InvalidRegistrationException("The client name must not be empty");
            }
            // Client Type
            if (StringUtils.isEmpty(appType)) {
                throw new InvalidRegistrationException("The client type must not be empty");
            }
            if (!("confidential".equals(appType) || "public".equals(appType))) {
                throw new InvalidRegistrationException("An invalid client type was specified: "
                    + StringEscapeUtils.escapeHtml4(appType));
            }
            // Client ID
            String clientId = generateClientId();
            boolean isConfidential = "confidential".equals(appType);
            // Client Secret
            String clientSecret = isConfidential
                ? generateClientSecret()
                : null;

            Client newClient = new Client(clientId, clientSecret, isConfidential, appName);

            // User who registered this client
            String userName = getUserName();
            UserSubject userSubject = new OidcUserSubject(userName);
            newClient.setResourceOwnerSubject(userSubject);

            // Client Registration Time
            newClient.setRegisteredAt(System.currentTimeMillis() / 1000);

            updateClientDetails(newClient, audience, redirectURI, logoutURI, homeRealm);

            // Client Scopes
            if (clientScopes != null && !clientScopes.isEmpty()) {
                newClient.setRegisteredScopes(new ArrayList<>(clientScopes.keySet()));
            }

            return Response.ok(registerNewClient(newClient)).build();
        } catch (InvalidRegistrationException ex) {
            // For the view handlers to handle it
            return Response.ok(new InvalidRegistration(ex.getMessage())).build();
        }
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    @Path("/{id}")
    public Response editForm(@PathParam("id") String clientId,
                             @FormParam("client_name") String appName,
                             @FormParam("client_audience") String audience,
                             @FormParam("client_redirectURI") String redirectURI,
                             @FormParam("client_logoutURI") String logoutURI,
                             @FormParam("client_homeRealm") String homeRealm,
                             @FormParam("client_csrfToken") String csrfToken
    ) {
        try {
            // CSRF
            checkCSRFToken(csrfToken);
            // checkSecurityContext();
            Client client = getRegisteredClient(clientId);

            // Client Name
            if (StringUtils.isEmpty(appName)) {
                throw new InvalidRegistrationException("The client name must not be empty");
            }

            updateClientDetails(client, audience, redirectURI, logoutURI, homeRealm);

            if (!client.getApplicationName().equals(appName)) {
                Collection<Client> clientRegistrations = getClientRegistrations(
                    client.getResourceOwnerSubject().getLogin());
                for (Iterator<Client> it = clientRegistrations.iterator(); it.hasNext();) {
                    Client c = it.next();
                    if (c.getClientId().equals(clientId)) {
                        it.remove();
                        break;
                    }
                }
                client.setApplicationName(appName);
                updateClientApplicationName(client, clientRegistrations);
                clientRegistrations.add(client);
            }

            clientProvider.setClient(client);

            return Response.ok(client).build();
        } catch (InvalidRegistrationException ex) {
            // For the view handlers to handle it
            return Response.ok(new InvalidRegistration(ex.getMessage())).build();
        }
    }

    private void updateClientDetails(final Client client,
        String audience, String redirectURI, String logoutURI, String homeRealm) {
        // Client Redirect URIs
        if (!StringUtils.isEmpty(redirectURI)) {
            String[] allUris = redirectURI.trim().split(" ");
            List<String> redirectUris = new ArrayList<>(allUris.length);
            for (String uri : allUris) {
                if (!StringUtils.isEmpty(uri)) {
                    if (!isValidURI(uri, false)) {
                        throw new InvalidRegistrationException("An invalid redirect URI was specified: "
                            + StringEscapeUtils.escapeHtml4(uri));
                    }
                    redirectUris.add(uri);
                }
            }
            client.setRedirectUris(redirectUris);
        } else {
            client.setRedirectUris(Collections.emptyList());
        }

        // Client Logout URI
        if (!StringUtils.isEmpty(logoutURI)) {
            String[] logoutUris = logoutURI.split(" ");
            for (String uri : logoutUris) {
                if (!isValidURI(uri, false)) {
                    throw new InvalidRegistrationException("An invalid logout URI was specified: "
                        + StringEscapeUtils.escapeHtml4(uri));
                }
            }
            //TODO: replace this code with newClient.setLogoutUri() once it becomes available
            client.getProperties().put("post_logout_redirect_uris", logoutURI);
        } else {
            client.getProperties().remove("post_logout_redirect_uris");
        }

        // Client Audience URIs
        if (!StringUtils.isEmpty(audience)) {
            String[] auds = audience.trim().split(" ");
            List<String> registeredAuds = new ArrayList<>(auds.length);
            for (String aud : auds) {
                if (!StringUtils.isEmpty(aud)) {
                    if (!isValidURI(aud, true)) {
                        throw new InvalidRegistrationException("An invalid audience URI was specified: "
                            + StringEscapeUtils.escapeHtml4(aud));
                    }
                    registeredAuds.add(aud);
                }
            }
            client.setRegisteredAudiences(registeredAuds);
        } else {
            client.setRegisteredAudiences(Collections.emptyList());
        }

        // Client Realm
        if (homeRealm != null) {
            client.setHomeRealm(homeRealm);
            if (homeRealms.containsKey(homeRealm)) {
                client.getProperties().put("homeRealmAlias", homeRealms.get(homeRealm));
            } else {
                client.getProperties().remove("homeRealmAlias");
            }
        }
    }

    private void checkSecurityContext() {
        SecurityContext sc = mc.getSecurityContext();
        if (sc == null || sc.getUserPrincipal() == null) {
            throw ExceptionUtils.toNotAuthorizedException(null,  null); 
        }
        if (userRole != null && !sc.isUserInRole(userRole)) {
            throw ExceptionUtils.toForbiddenException(null,  null); 
        }
    }
    private void checkCSRFToken(String csrfToken) {
        // CSRF
        HttpServletRequest httpRequest = mc.getHttpServletRequest();
        String savedToken = CSRFUtils.getCSRFToken(httpRequest, false);
        if (StringUtils.isEmpty(csrfToken) || StringUtils.isEmpty(savedToken)
            || !savedToken.equals(csrfToken)) {
            throw new InvalidRegistrationException("Invalid CSRF Token");
        }
    }

    private static boolean isValidURI(String uri, boolean requireHttps) {

        final String[] schemes;

        if (requireHttps) {
            schemes = new String[] {"https"};
        } else {
            schemes = new String[] {"https", "http"};
        }

        UrlValidator urlValidator = new UrlValidator(schemes, UrlValidator.ALLOW_LOCAL_URLS);
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

    protected RegisteredClients registerNewClient(Client newClient) {
        Collection<Client> clientRegistrations = getClientRegistrations(newClient.getResourceOwnerSubject().getLogin());
        updateClientApplicationName(newClient, clientRegistrations);

        clientProvider.setClient(newClient);
        clientRegistrations.add(newClient);
        return new RegisteredClients(clientRegistrations);
    }

    private static void updateClientApplicationName(Client client, Collection<Client> clientRegistrations) {
        Set<String> names = new HashSet<>();
        for (Client c : clientRegistrations) {
            names.add(c.getApplicationName());
        }
        if (names.contains(client.getApplicationName())) {
            String newName = client.getApplicationName();
            SortedSet<Integer> numbers = new TreeSet<>();
            for (String name : names) {
                if (name.startsWith(newName) && !name.equals(newName)) {
                    try {
                        numbers.add(Integer.valueOf(name.substring(newName.length())));
                    } catch (Exception ex) {
                        // can be characters, continue;
                    }
                }
            }
            int nextNumber = numbers.isEmpty() ? 2 : numbers.last() + 1;
            client.setApplicationName(newName + nextNumber);
        }
    }

    protected Collection<Client> getClientRegistrations() {
        return getClientRegistrations(getUserName());
    }

    protected Collection<Client> getClientRegistrations(String userName) {
        Collection<Client> userClientRegs = registrations.get(userName);
        if (userClientRegs == null) {
            // or the registration date comparison - this can be driven from UI
            // example, Sort Clients By Name/Date/etc
            userClientRegs = new TreeSet<>(Comparator.comparing(Client::getApplicationName));
            registrations.put(userName, userClientRegs);
        }
        return userClientRegs;
    }

    private String getUserName() {
        SecurityContext sc = mc.getSecurityContext();
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
            if (c.getResourceOwnerSubject() != null) {
                String userName = c.getResourceOwnerSubject().getLogin();
                getClientRegistrations(userName).add(c);
            }
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

    public void setAdditionalTLDs(List<String> additionalTLDs) {
        // Support additional top level domains
        if (additionalTLDs != null && !additionalTLDs.isEmpty()) {
            try {
                LOG.info("Adding the following additional Top Level Domains: " + additionalTLDs);
                DomainValidator.updateTLDOverride(ArrayType.GENERIC_PLUS, additionalTLDs.toArray(new String[0]));
            } catch (IllegalStateException ex) {
                //
            }
        }
    }

    public void setUserRole(String userRole) {
        this.userRole = userRole;
    }

}
