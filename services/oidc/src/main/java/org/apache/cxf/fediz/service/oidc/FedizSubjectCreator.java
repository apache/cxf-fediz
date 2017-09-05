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

import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriBuilder;

import org.w3c.dom.Element;

import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.ClaimCollection;
import org.apache.cxf.fediz.core.ClaimTypes;
import org.apache.cxf.fediz.core.FedizConstants;
import org.apache.cxf.fediz.core.FedizPrincipal;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.cxf.rs.security.oauth2.provider.SubjectCreator;
import org.apache.cxf.rs.security.oauth2.utils.OAuthConstants;
import org.apache.cxf.rs.security.oidc.common.AbstractUserInfo;
import org.apache.cxf.rs.security.oidc.common.IdToken;
import org.apache.cxf.rs.security.oidc.idp.OidcUserSubject;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.joda.time.DateTime;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Issuer;


public class FedizSubjectCreator implements SubjectCreator {
    private static final String ROLES_SCOPE = "roles";

    private static final String PROFILE_SCOPE = "profile";
    private static final String EMAIL_SCOPE = "email";
    private static final String ADDRESS_SCOPE = "address";
    private static final String PHONE_SCOPE = "phone";
    private static final List<String> PROFILE_CLAIMS = Arrays.asList(AbstractUserInfo.NAME_CLAIM,
                                                                    AbstractUserInfo.FAMILY_NAME_CLAIM,
                                                                    AbstractUserInfo.GIVEN_NAME_CLAIM,
                                                                    AbstractUserInfo.MIDDLE_NAME_CLAIM,
                                                                    AbstractUserInfo.NICKNAME_CLAIM,
                                                                    AbstractUserInfo.PREFERRED_USERNAME_CLAIM,
                                                                    AbstractUserInfo.PROFILE_CLAIM,
                                                                    AbstractUserInfo.PICTURE_CLAIM,
                                                                    AbstractUserInfo.WEBSITE_CLAIM,
                                                                    AbstractUserInfo.GENDER_CLAIM,
                                                                    AbstractUserInfo.BIRTHDATE_CLAIM,
                                                                    AbstractUserInfo.ZONEINFO_CLAIM,
                                                                    AbstractUserInfo.LOCALE_CLAIM,
                                                                    AbstractUserInfo.UPDATED_AT_CLAIM);
    private static final List<String> EMAIL_CLAIMS = Arrays.asList(AbstractUserInfo.EMAIL_CLAIM,
                                                                  AbstractUserInfo.EMAIL_VERIFIED_CLAIM);
    private static final List<String> ADDRESS_CLAIMS = Arrays.asList(AbstractUserInfo.ADDRESS_CLAIM);
    private static final List<String> PHONE_CLAIMS = Arrays.asList(AbstractUserInfo.PHONE_CLAIM);

    private static final Map<String, List<String>> SCOPES_MAP;
    static {
        SCOPES_MAP = new HashMap<>();
        SCOPES_MAP.put(PHONE_SCOPE, PHONE_CLAIMS);
        SCOPES_MAP.put(EMAIL_SCOPE, EMAIL_CLAIMS);
        SCOPES_MAP.put(ADDRESS_SCOPE, ADDRESS_CLAIMS);
        SCOPES_MAP.put(PROFILE_SCOPE, PROFILE_CLAIMS);
    }

    private String issuer;
    private long defaultTimeToLive = 3600L;
    private Map<String, String> supportedClaims = Collections.emptyMap();

    @Override
    public OidcUserSubject createUserSubject(MessageContext mc,
                                         MultivaluedMap<String, String> params) throws OAuthServiceException {
        Principal principal = mc.getSecurityContext().getUserPrincipal();

        if (!(principal instanceof FedizPrincipal)) {
            throw new OAuthServiceException("Unsupported Principal");
        }
        FedizPrincipal fedizPrincipal = (FedizPrincipal)principal;

        // In the future FedizPrincipal will likely have JWT claims already prepared,
        // with IdToken being initialized here from those claims
        OidcUserSubject oidcSub = new OidcUserSubject();
        oidcSub.setLogin(fedizPrincipal.getName());

        oidcSub.setId(fedizPrincipal.getName());

        IdToken idToken = convertToIdToken(mc,
                                           fedizPrincipal.getLoginToken(),
                                           oidcSub.getLogin(),
                                           oidcSub.getId(),
                                           fedizPrincipal.getClaims(),
                                           fedizPrincipal.getRoleClaims(),
                                           params);
        oidcSub.setIdToken(idToken);
        oidcSub.setRoles(fedizPrincipal.getRoleClaims());
        // UserInfo can be populated and set on OidcUserSubject too.
        // UserInfoService will create it otherwise.

        return oidcSub;
    }

    private IdToken convertToIdToken(MessageContext mc,
            Element samlToken,
            String subjectName,
            String subjectId,
            ClaimCollection claims,
            List<String> roles,
            MultivaluedMap<String, String> params) {
        // The current SAML Assertion represents an authentication record.
        // It has to be translated into IdToken (JWT) so that it can be returned
        // to client applications participating in various OIDC flows.

        IdToken idToken = new IdToken();

        //TODO: make the mapping between the subject name and IdToken claim configurable
        idToken.setPreferredUserName(subjectName);
        idToken.setSubject(subjectId);

        Assertion saml2Assertion = getSaml2Assertion(samlToken);
        if (saml2Assertion != null) {
            // issueInstant
            DateTime issueInstant = saml2Assertion.getIssueInstant();
            if (issueInstant != null) {
                idToken.setIssuedAt(issueInstant.getMillis() / 1000);
            }

            // expiryTime
            if (saml2Assertion.getConditions() != null) {
                DateTime expires = saml2Assertion.getConditions().getNotOnOrAfter();
                if (expires != null) {
                    idToken.setExpiryTime(expires.getMillis() / 1000);
                }
            }

            // authInstant
            if (!saml2Assertion.getAuthnStatements().isEmpty()) {
                DateTime authInstant =
                saml2Assertion.getAuthnStatements().get(0).getAuthnInstant();
                idToken.setAuthenticationTime(authInstant.getMillis() / 1000L);
            }
        }
        // Check if default issuer, issuedAt and expiryTime values have to be set
        if (issuer != null) {
            String realIssuer = null;
            if (issuer.startsWith("/")) {
                UriBuilder ub = mc.getUriInfo().getBaseUriBuilder();
                realIssuer = ub.path(issuer).build().toString();
            } else {
                realIssuer = issuer;
            }
            idToken.setIssuer(realIssuer);
        } else if (saml2Assertion != null) {
            Issuer assertionIssuer = saml2Assertion.getIssuer();
            if (assertionIssuer != null) {
                idToken.setIssuer(assertionIssuer.getValue());
            }
        }

        long currentTimeInSecs = System.currentTimeMillis() / 1000;
        if (idToken.getIssuedAt() == null) {
            idToken.setIssuedAt(currentTimeInSecs);
        }
        if (idToken.getExpiryTime() == null) {
            idToken.setExpiryTime(currentTimeInSecs + defaultTimeToLive);
        }

        List<String> requestedClaimsList = new ArrayList<String>();
        //Derive claims from scope
        String requestedScope = params.getFirst(OAuthConstants.SCOPE);
        if (requestedScope != null && !requestedScope.isEmpty()) {
            String[] scopes = requestedScope.split(" ");
            //TODO: Note that if the consent screen enabled then it is feasible
            // that the claims added in this code after mapping the scopes to claims
            // may need to be removed if the user disapproves the related scope

            // standard scope to claims mapping:
            requestedClaimsList.addAll(getScopeClaims(scopes));
            // custom scopes to claims mapping
            requestedClaimsList.addAll(getCustomScopeClaims(scopes));
        }
        // Additional claims requested
        String requestedClaims = params.getFirst("claims");
        if (requestedClaims != null && !requestedClaims.isEmpty()) {
            requestedClaimsList.addAll(Arrays.asList(requestedClaims.trim().split(" ")));
        }

        // Map claims
        if (claims != null) {
            String firstName = null;
            String lastName = null;
            for (Claim c : claims) {
                if (!(c.getValue() instanceof String)) {
                    continue;
                }
                if (ClaimTypes.FIRSTNAME.equals(c.getClaimType())) {
                    idToken.setGivenName((String)c.getValue());
                    firstName = (String)c.getValue();
                } else if (ClaimTypes.LASTNAME.equals(c.getClaimType())) {
                    idToken.setFamilyName((String)c.getValue());
                    lastName = (String)c.getValue();
                } else if (ClaimTypes.EMAILADDRESS.equals(c.getClaimType())) {
                    idToken.setEmail((String)c.getValue());
                } else if (supportedClaims.containsKey(c.getClaimType().toString())
                    && requestedClaimsList.contains(supportedClaims.get(c.getClaimType().toString()))) {
                    idToken.setClaim(supportedClaims.get(c.getClaimType().toString()), (String)c.getValue());
                }

            }
            if (firstName != null && lastName != null) {
                idToken.setName(firstName + " " + lastName);
            }
        }

        if (roles != null && !roles.isEmpty()
            && supportedClaims.containsKey(FedizConstants.DEFAULT_ROLE_URI.toString())) {

            String roleClaimName = supportedClaims.get(FedizConstants.DEFAULT_ROLE_URI.toString());
            if (requestedClaimsList.contains(roleClaimName)) {
                idToken.setClaim(roleClaimName, roles);
            }
        }

        return idToken;
    }

    private static List<String> getScopeClaims(String... scope) {
        List<String> claims = new ArrayList<>();
        if (scope != null) {
            for (String s : scope) {
                if (SCOPES_MAP.containsKey(s)) {
                    claims.addAll(SCOPES_MAP.get(s));
                }
            }
        }
        return claims;
    }


    private List<String> getCustomScopeClaims(String[] scopes) {
        // For now the only custom scope (to claims) mapping Fediz supports is
        // roles where the scope name is expected to be 'roles' and the role name must be configured
        String roleClaimName = supportedClaims.get(FedizConstants.DEFAULT_ROLE_URI.toString());
        if (roleClaimName != null && Arrays.asList(scopes).contains(ROLES_SCOPE)) {
            return Collections.singletonList(roleClaimName);
        } else {
            return Collections.emptyList();
        }

    }

    private Assertion getSaml2Assertion(Element samlToken) {
        // Should a null assertion lead to the exception ?
        try {
            SamlAssertionWrapper wrapper = new SamlAssertionWrapper(samlToken);
            return wrapper.getSaml2();
        } catch (WSSecurityException ex) {
            throw new OAuthServiceException("Error converting SAML token", ex);
        }

    }


    public void setIdTokenIssuer(String idTokenIssuer) {
        this.issuer = idTokenIssuer;
    }


    public void setIdTokenTimeToLive(long idTokenTimeToLive) {
        this.defaultTimeToLive = idTokenTimeToLive;
    }

    /**
     * Set a map of supported claims. The map is from a SAML ClaimType URI String to a claim value that is
     * sent in the claims parameter. So for example:
     * http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role -> role
     * If the token contains a the former, and the OpenId claims contains the latter, then the claim value
     * will be encoded in the IdToken using the latter key.
     */
    public void setSupportedClaims(Map<String, String> supportedClaims) {
        this.supportedClaims = supportedClaims;
    }

}
