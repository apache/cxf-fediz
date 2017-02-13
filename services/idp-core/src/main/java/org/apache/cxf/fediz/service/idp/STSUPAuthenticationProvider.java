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
import javax.xml.namespace.QName;

import org.apache.cxf.Bus;
import org.apache.cxf.ws.security.SecurityConstants;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.wss4j.dom.WSConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * An authentication provider to authenticate a Username/Password to the STS
 */
public class STSUPAuthenticationProvider extends STSAuthenticationProvider {

    private static final Logger LOG = LoggerFactory.getLogger(STSUPAuthenticationProvider.class);

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
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
        sts.setWsdlLocation(wsdlLocation);
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

            if (getCustomSTSParameter() != null) {
                HttpServletRequest request =
                    ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
                String authRealmParameter = request.getParameter(getCustomSTSParameter());
                LOG.debug("Found {} custom STS parameter {}", getCustomSTSParameter(), authRealmParameter);
                if (authRealmParameter != null) {
                    sts.setCustomContent(authRealmParameter);
                }
            }

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

        } catch (Exception ex) {
            LOG.info("Failed to authenticate user '" + usernamePasswordToken.getName() + "'", ex);
            return null;
        }

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }

}
