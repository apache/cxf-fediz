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
package org.apache.cxf.fediz.service.idp;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import org.apache.cxf.Bus;
import org.apache.cxf.service.factory.ServiceConstructionException;
import org.apache.cxf.ws.security.SecurityConstants;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.wss4j.dom.WSConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * An authentication provider to authenticate a Username/Password to the STS
 */
public class STSUPAuthenticationProvider extends STSAuthenticationProvider {

    private static final Logger LOG = LoggerFactory.getLogger(STSUPAuthenticationProvider.class);

    private RequestCache requestCache = new HttpSessionRequestCache();

    @Override
    public Authentication authenticate(Authentication authentication) {
        // We only handle UsernamePasswordAuthenticationTokens
        if (!(authentication instanceof UsernamePasswordAuthenticationToken)) {
            return null;
        }

        Bus cxfBus = getBus();
        IdpSTSClient sts = new IdpSTSClient(cxfBus);
        sts.setAddressingNamespace("http://www.w3.org/2005/08/addressing");
        if (tokenType != null && tokenType.length() > 0) {
            sts.setTokenType(tokenType);
        } else {
            sts.setTokenType(WSConstants.WSS_SAML2_TOKEN_TYPE);
        }
        sts.setKeyType(HTTP_DOCS_OASIS_OPEN_ORG_WS_SX_WS_TRUST_200512_BEARER);
        sts.setWsdlLocation(getWsdlLocation());
        sts.setServiceQName(new QName(namespace, wsdlService));
        sts.setEndpointQName(new QName(namespace, wsdlEndpoint));

        sts.getProperties().putAll(properties);
        if (use200502Namespace) {
            sts.setNamespace(HTTP_SCHEMAS_XMLSOAP_ORG_WS_2005_02_TRUST);
        }

        if (lifetime != null) {
            sts.setEnableLifetime(true);
            sts.setTtl(lifetime.intValue());
        }

        return handleUsernamePassword((UsernamePasswordAuthenticationToken)authentication, sts);
    }

    private Authentication handleUsernamePassword(
        UsernamePasswordAuthenticationToken usernamePasswordToken,
        IdpSTSClient sts
    ) {
        sts.getProperties().put(SecurityConstants.USERNAME, usernamePasswordToken.getName());
        sts.getProperties().put(SecurityConstants.PASSWORD, (String)usernamePasswordToken.getCredentials());

        try {

            sts.setCustomContent(getCustomSTSParameterValue());

            // Line below may be uncommented for debugging
            // setTimeout(sts.getClient(), 3600000L);

            SecurityToken token = sts.requestSecurityToken(this.appliesTo);

            List<GrantedAuthority> authorities = createAuthorities(token);

            UsernamePasswordAuthenticationToken upat =
                new UsernamePasswordAuthenticationToken(usernamePasswordToken.getName(),
                                                        usernamePasswordToken.getCredentials(),
                                                        authorities);

            STSUserDetails details = new STSUserDetails(usernamePasswordToken.getName(),
                                                        (String)usernamePasswordToken.getCredentials(),
                                                        authorities,
                                                        token);
            upat.setDetails(details);

            LOG.debug("[IDP_TOKEN={}] provided for user '{}'", token.getId(), usernamePasswordToken.getName());
            return upat;

        } catch (ServiceConstructionException ex) {
            // Explictly catch ServiceConstructionException here - this allows us to handle the case of
            // the STS being down separately
            LOG.info("Failed to authenticate user '" + usernamePasswordToken.getName() + "'", ex);
            throw new AuthenticationServiceException("Failed to authenticate user '"
                + usernamePasswordToken.getName(), ex);
        } catch (Exception ex) {
            LOG.info("Failed to authenticate user '" + usernamePasswordToken.getName() + "'", ex);
            return null;
        }

    }

    /**
     * If customSTSParameter has been set, this method will lookup :
     * <ul>
     *     <ol> in http parameters</ol>
     *     <ol> if not found in the requestCache from Spring Security.
     *     This lookup is necessary whenever you use Spring Security form-login since
     *     it redirects you to an login-url and stores original request in the requestCache.</ol>
     * </ul>
     */
    private String getCustomSTSParameterValue() {
        String authRealmParameter = null;
        if (getCustomSTSParameter() != null) {
            HttpServletRequest request =
                    ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
            authRealmParameter = request.getParameter(getCustomSTSParameter());
            if (authRealmParameter == null) {
                HttpServletResponse response =
                        ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getResponse();
                SavedRequest savedRequest = requestCache.getRequest(request, response);
                if (savedRequest != null) {
                    String[] parameterValues = savedRequest.getParameterValues(this.getCustomSTSParameter());
                    if (parameterValues != null && parameterValues.length > 0) {
                        authRealmParameter = parameterValues[0];
                    }
                }
            }
            LOG.debug("Found {} custom STS parameter {}", getCustomSTSParameter(), authRealmParameter);
        }
        return authRealmParameter;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }

    public void setRequestCache(RequestCache requestCache) {
        this.requestCache = requestCache;
    }
}
