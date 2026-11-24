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

package org.apache.cxf.fediz.spring.authentication;

import java.util.List;

import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.core.processor.FedizProcessor;
import org.apache.cxf.fediz.core.processor.FedizProcessorFactory;
import org.apache.cxf.fediz.core.processor.FedizRequest;
import org.apache.cxf.fediz.core.processor.FedizResponse;
import org.apache.cxf.fediz.spring.FederationConfig;
import org.apache.cxf.fediz.spring.SpringFedizMessageSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.util.Assert;


/**
 * This {@link AuthenticationProvider} implements the integration with the Identity Provider
 * based on the WS-Federation Passive Requestor Profile.
 */
public class FederationAuthenticationProvider implements AuthenticationProvider, InitializingBean, MessageSourceAware {
    private static final Logger LOG = LoggerFactory.getLogger(FederationAuthenticationProvider.class);

    protected MessageSourceAccessor messages = SpringFedizMessageSource.getAccessor();

    private AuthenticationUserDetailsService<FederationResponseAuthenticationToken> authenticationUserDetailsService;
    private FederationConfig federationConfig;

    private final UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

    public AuthenticationUserDetailsService<FederationResponseAuthenticationToken>
    getAuthenticationUserDetailsService() {
        return authenticationUserDetailsService;
    }

    public void setAuthenticationUserDetailsService(
        AuthenticationUserDetailsService<FederationResponseAuthenticationToken> authenticationUserDetailsService) {
        this.authenticationUserDetailsService = authenticationUserDetailsService;
    }

    public FederationConfig getFederationConfig() {
        return federationConfig;
    }

    public void setFederationConfig(FederationConfig federationConfig) {
        this.federationConfig = federationConfig;
    }



    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.authenticationUserDetailsService, "An authenticationUserDetailsService must be set");
        Assert.notNull(this.messages, "A message source must be set");
        Assert.notNull(this.federationConfig, "FederationConfig cannot be null.");
    }

    public Authentication authenticate(Authentication authentication) {
        if (!supports(authentication.getClass())) {
            return null;
        }

        if (!(authentication instanceof UsernamePasswordAuthenticationToken)) {
            return null;
        }

        // Ensure credentials are provided
        if (authentication.getCredentials() == null || "".equals(authentication.getCredentials())) {
            throw new BadCredentialsException(messages.getMessage("FederationAuthenticationProvider.noSignInRequest",
                    "Failed to get SignIn request"));
        }

        FederationAuthenticationToken result = this.authenticateNow(authentication);
        result.setDetails(authentication.getDetails());
        return result;
    }

    private FederationAuthenticationToken authenticateNow(final Authentication authentication) {
        try {
            FedizRequest wfReq = (FedizRequest)authentication.getCredentials();

            FedizContext fedContext = federationConfig.getFedizContext();
            FedizProcessor wfProc =
                FedizProcessorFactory.newFedizProcessor(fedContext.getProtocol());
            FedizResponse wfRes = wfProc.processRequest(wfReq, fedContext);

            validateAudienceRestriction(wfRes.getAudience(), fedContext.getAudienceUris());

            final UserDetails userDetails = loadUserByFederationResponse(wfRes);
            userDetailsChecker.check(userDetails);
            return new FederationAuthenticationToken(userDetails, authentication.getCredentials(),
                    authoritiesMapper.mapAuthorities(userDetails.getAuthorities()), userDetails, wfRes);
        } catch (Exception e) {
            LOG.error("Failed to validate SignIn request", e);
            throw new BadCredentialsException(e.getMessage(), e);
        }
    }

    /**
     * Validate the AudienceRestriction of the received token against the configured list of audience URIs.
     * A token without an audience is only accepted if no audience URIs are configured, and a token with an
     * audience is only accepted if it matches one of the configured audience URIs.
     *
     * @param audience the audience of the received token (may be null)
     * @param audienceURIs the configured audience URIs
     * @throws BadCredentialsException if the audience is not valid for this relying party
     */
    protected void validateAudienceRestriction(String audience, List<String> audienceURIs) {
        boolean validAudience = audienceURIs.isEmpty() && audience == null;
        if (!validAudience && audience != null) {
            for (String a : audienceURIs) {
                if (audience.startsWith(a)) {
                    validAudience = true;
                    LOG.debug("Token audience matches with valid URIs.");
                    break;
                }
            }
        }

        if (!validAudience) {
            LOG.warn("Token AudienceRestriction [{}] doesn't match with specified list of URIs.", audience);
            LOG.debug("Authenticated URIs are: {}", audienceURIs);
            throw new BadCredentialsException(messages.getMessage("FederationAuthenticationProvider.badAudience",
                    "Token AudienceRestriction doesn't match with the configured audience URIs"));
        }
    }

    /**
     * Template method for retrieving the UserDetails based on the federation response (wresult parameter).
     *
     * @param response The WS Federation response
     * @return the UserDetails.
     */
    protected UserDetails loadUserByFederationResponse(final FedizResponse response) {
        final FederationResponseAuthenticationToken token = new FederationResponseAuthenticationToken(response);
        return this.authenticationUserDetailsService.loadUserDetails(token);
    }

    public void setMessageSource(final MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
    }

    public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
        this.authoritiesMapper = authoritiesMapper;
    }

    public boolean supports(final Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication))
            || (FederationAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
