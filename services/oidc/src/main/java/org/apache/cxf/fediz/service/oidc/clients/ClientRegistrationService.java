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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
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

import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.DomainValidator.ArrayType;
import org.apache.commons.validator.routines.UrlValidator;
import org.apache.cxf.common.logging.LogUtils;
import org.apache.cxf.common.util.Base64UrlUtility;
import org.apache.cxf.common.util.StringUtils;
import org.apache.cxf.fediz.service.oidc.CSRFUtils;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.PhaseInterceptorChain;
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
import org.apache.cxf.transport.http.AbstractHTTPDestination;

@Path("/")
public class ClientRegistrationService {

    private static final Logger LOG = LogUtils.getL7dLogger(ClientRegistrationService.class);

    private Map<String, Collection<Client>> registrations = new HashMap<>();
    private Map<String, Set<String>> clientNames = new HashMap<>();
    private OAuthDataProvider dataProvider;
    private ClientRegistrationProvider clientProvider;
    private Map<String, String> homeRealms = new LinkedHashMap<String, String>();
    private boolean protectIdTokenWithClientSecret;
    private Map<String, String> clientScopes;

    private SecurityContext sc;

    @Context
    public void setSecurityContext(SecurityContext securityContext) {
        this.sc = securityContext;
    }

    @GET
    @Produces(MediaType.TEXT_HTML)
    @Path("/register")
    public RegisterClient registerStart() {
        return new RegisterClient(homeRealms);
    }

    @GET
    @Produces(MediaType.TEXT_HTML)
    @Path("/")
    public RegisteredClients getClients() {
        return new RegisteredClients(getClientRegistrations());
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
    public RegisteredClients removeClient(@PathParam("id") String id,
                                          @FormParam("client_csrfToken") String csrfToken) {
        // CSRF
        checkCSRFToken(csrfToken);

        Collection<Client> clients = getClientRegistrations();
        for (Iterator<Client> it = clients.iterator(); it.hasNext();) {
            Client c = it.next();
            if (c.getClientId().equals(id)) {
                clientProvider.removeClient(id);
                it.remove();
                Set<String> names = clientNames.get(getUserName());
                if (names != null) {
                    names.remove(c.getApplicationName());
                }
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
        Comparator<ServerAccessToken> tokenComp = new TokenComparator();
        UserSubject subject = new OidcUserSubject(getUserName());
        List<ServerAccessToken> accessTokens =
            new ArrayList<ServerAccessToken>(dataProvider.getAccessTokens(c, subject));
        Collections.sort(accessTokens, tokenComp);
        List<RefreshToken> refreshTokens =
                new ArrayList<RefreshToken>(dataProvider.getRefreshTokens(c, subject));
        Collections.sort(refreshTokens, tokenComp);
        return new ClientTokens(c, accessTokens, refreshTokens);
    }
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    @Path("/{id}/at/{tokenId}/revoke")
    public ClientTokens revokeClientAccessToken(@PathParam("id") String clientId,
                                                      @PathParam("tokenId") String tokenId,
                                                      @FormParam("client_csrfToken") String csrfToken) {
        // CSRF
        checkCSRFToken(csrfToken);

        return doRevokeClientToken(clientId, tokenId, OAuthConstants.ACCESS_TOKEN);
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    @Path("/{id}/rt/{tokenId}/revoke")
    public ClientTokens revokeClientRefreshToken(@PathParam("id") String clientId,
                                                      @PathParam("tokenId") String tokenId,
                                                      @FormParam("client_csrfToken") String csrfToken) {
        // CSRF
        checkCSRFToken(csrfToken);

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
            UserSubject subject = new OidcUserSubject(getUserName());
            List<ServerAuthorizationCodeGrant> codeGrants = new ArrayList<>(
               ((AuthorizationCodeDataProvider)dataProvider).getCodeGrants(c, subject));
            Collections.sort(codeGrants, new CodeGrantComparator());
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

            // Client Name
            if (StringUtils.isEmpty(appName)) {
                throwInvalidRegistrationException("The client name must not be empty");
            }
            // Client Type
            if (StringUtils.isEmpty(appType)) {
                throwInvalidRegistrationException("The client type must not be empty");
            }
            if (!("confidential".equals(appType) || "public".equals(appType))) {
                throwInvalidRegistrationException("An invalid client type was specified: " + appType);
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
            String userName = sc.getUserPrincipal().getName();
            UserSubject userSubject = new OidcUserSubject(userName);
            newClient.setResourceOwnerSubject(userSubject);

            // Client Registration Time
            newClient.setRegisteredAt(System.currentTimeMillis() / 1000);

            // Client Realm
            if (homeRealm != null) {
                newClient.setHomeRealm(homeRealm);
                if (homeRealms.containsKey(homeRealm)) {
                    newClient.getProperties().put("homeRealmAlias", homeRealms.get(homeRealm));
                }
            }

            // Client Redirect URIs
            if (!StringUtils.isEmpty(redirectURI)) {
                String[] allUris = redirectURI.trim().split(" ");
                List<String> redirectUris = new LinkedList<String>();
                for (String uri : allUris) {
                    if (!StringUtils.isEmpty(uri)) {
                        if (!isValidURI(uri, false)) {
                            throwInvalidRegistrationException("An invalid redirect URI was specified: " + uri);
                        }
                        redirectUris.add(uri);
                    }
                }
                newClient.setRedirectUris(redirectUris);
            }
            // Client Logout URI
            if (!StringUtils.isEmpty(logoutURI)) {
                String[] logoutUris = logoutURI.split(" ");
                for (String uri : logoutUris) {
                    if (!isValidURI(uri, false)) {
                        throwInvalidRegistrationException("An invalid logout URI was specified: " + uri);
                    }
                }
                //TODO: replace this code with newClient.setLogoutUri() once it becomes available
                newClient.getProperties().put("post_logout_redirect_uris", logoutURI);
            }

            // Client Audience URIs
            if (!StringUtils.isEmpty(audience)) {
                String[] auds = audience.trim().split(" ");
                List<String> registeredAuds = new LinkedList<String>();
                for (String aud : auds) {
                    if (!StringUtils.isEmpty(aud)) {
                        if (!isValidURI(aud, true)) {
                            throwInvalidRegistrationException("An invalid audience URI was specified: " + aud);
                        }
                        registeredAuds.add(aud);
                    }
                }
                newClient.setRegisteredAudiences(registeredAuds);
            }

            // Client Scopes
            if (clientScopes != null && !clientScopes.isEmpty()) {
                newClient.setRegisteredScopes(new ArrayList<String>(clientScopes.keySet()));
            }
            return Response.ok(registerNewClient(newClient)).build();
        } catch (InvalidRegistrationException ex) {
            // For the view handlers to handle it
            return Response.ok(new InvalidRegistration(ex.getMessage())).build();
        }
    }

    private void checkCSRFToken(String csrfToken) {
        // CSRF
        Message message = PhaseInterceptorChain.getCurrentMessage();
        HttpServletRequest httpRequest = (HttpServletRequest) message.get(AbstractHTTPDestination.HTTP_REQUEST);
        String savedToken = CSRFUtils.getCSRFToken(httpRequest, false);
        if (StringUtils.isEmpty(csrfToken) || StringUtils.isEmpty(savedToken)
            || !savedToken.equals(csrfToken)) {
            throwInvalidRegistrationException("Invalid CSRF Token");
        }
    }

    private void throwInvalidRegistrationException(String error) {
        throw new InvalidRegistrationException(error);
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

    protected RegisteredClients registerNewClient(Client newClient) {
        String userName = newClient.getResourceOwnerSubject().getLogin();
        Set<String> names = clientNames.get(userName);
        if (names == null) {
            names = new HashSet<>();
            clientNames.put(userName, names);
        } else if (names.contains(newClient.getApplicationName())) {
            String newName = newClient.getApplicationName();
            SortedSet<Integer> numbers = new TreeSet<Integer>();
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
            newClient.setApplicationName(newName + nextNumber);
        }
        names.add(newClient.getApplicationName());

        clientProvider.setClient(newClient);
        Collection<Client> clientRegistrations = getClientRegistrations();
        clientRegistrations.add(newClient);
        return new RegisteredClients(clientRegistrations);
    }

    protected Collection<Client> getClientRegistrations() {
        String userName = getUserName();
        return getClientRegistrations(userName);
    }

    protected Collection<Client> getClientRegistrations(String userName) {
        Collection<Client> userClientRegs = registrations.get(userName);
        if (userClientRegs == null) {
            userClientRegs = new TreeSet<Client>(new ClientComparator());
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
            if (c.getResourceOwnerSubject() != null) {
                String userName = c.getResourceOwnerSubject().getLogin();
                getClientRegistrations(userName).add(c);
                Set<String> names = clientNames.get(userName);
                if (names == null) {
                    names = new HashSet<>();
                    clientNames.put(userName, names);
                }
                names.add(c.getApplicationName());
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
                String[] tldsToAddArray = additionalTLDs.toArray(new String[additionalTLDs.size()]);
                LOG.info("Adding the following additional Top Level Domains: " + Arrays.toString(tldsToAddArray));
                DomainValidator.updateTLDOverride(ArrayType.GENERIC_PLUS, tldsToAddArray);
            } catch (IllegalStateException ex) {
                //
            }
        }
    }

    private static class ClientComparator implements Comparator<Client> {

        @Override
        public int compare(Client c1, Client c2) {
            // or the registration date comparison - this can be driven from UI
            // example, Sort Clients By Name/Date/etc
            return c1.getApplicationName().compareTo(c2.getApplicationName());
        }

    }
    private static class TokenComparator implements Comparator<ServerAccessToken> {

        @Override
        public int compare(ServerAccessToken t1, ServerAccessToken t2) {
            return Long.compare(t1.getIssuedAt(), t2.getIssuedAt());
        }

    }
    private static class CodeGrantComparator implements Comparator<ServerAuthorizationCodeGrant> {

        @Override
        public int compare(ServerAuthorizationCodeGrant g1, ServerAuthorizationCodeGrant g2) {
            return Long.compare(g1.getIssuedAt(), g2.getIssuedAt());
        }

    }
}
