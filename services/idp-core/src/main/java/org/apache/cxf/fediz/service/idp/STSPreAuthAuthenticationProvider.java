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

import java.security.cert.X509Certificate;
import java.util.List;

import javax.xml.namespace.QName;

import org.w3c.dom.Document;
import org.apache.cxf.Bus;
import org.apache.cxf.fediz.core.util.DOMUtils;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.wss4j.dom.WSConstants;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.content.X509Data;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

/**
 * An authentication provider to authenticate a preauthenticated token to the STS
 */
public class STSPreAuthAuthenticationProvider extends STSAuthenticationProvider {

    private static final Logger LOG = LoggerFactory
            .getLogger(STSPreAuthAuthenticationProvider.class);

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // We only handle PreAuthenticatedAuthenticationTokens
        if (!(authentication instanceof PreAuthenticatedAuthenticationToken)) {
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

        return handlePreAuthenticated((PreAuthenticatedAuthenticationToken)authentication, sts);
    }

    private Authentication handlePreAuthenticated(
        PreAuthenticatedAuthenticationToken preauthenticatedToken,
        IdpSTSClient sts
    ) {
        X509Certificate cert = (X509Certificate)preauthenticatedToken.getCredentials();
        if (cert == null) {
            return null;
        }

        // Convert the received certificate to a DOM Element to write it out "OnBehalfOf"
        Document doc = DOMUtils.createDocument();
        X509Data certElem = new X509Data(doc);
        try {
            certElem.addCertificate(cert);
            sts.setOnBehalfOf(certElem.getElement());
        } catch (XMLSecurityException e) {
            LOG.debug("Error parsing a client certificate", e);
            return null;
        }

        try {
            // Line below may be uncommented for debugging
            // setTimeout(sts.getClient(), 3600000L);

            SecurityToken token = sts.requestSecurityToken(this.appliesTo);

            List<GrantedAuthority> authorities = createAuthorities(token);

            STSUserDetails details = new STSUserDetails(preauthenticatedToken.getName(),
                                                        "",
                                                        authorities,
                                                        token);

            preauthenticatedToken.setDetails(details);

            LOG.debug("[IDP_TOKEN={}] provided for user '{}'", token.getId(), preauthenticatedToken.getName());
            return preauthenticatedToken;

        } catch (Exception ex) {
            LOG.info("Failed to authenticate user '" + preauthenticatedToken.getName() + "'", ex);
            return null;
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(PreAuthenticatedAuthenticationToken.class);
    }

}
