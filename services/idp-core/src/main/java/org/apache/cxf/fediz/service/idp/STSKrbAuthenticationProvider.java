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

import java.security.Principal;
import java.security.PrivilegedActionException;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.xml.namespace.QName;

import org.apache.cxf.Bus;
import org.apache.cxf.fediz.service.idp.kerberos.KerberosServiceRequestToken;
import org.apache.cxf.fediz.service.idp.kerberos.KerberosTokenValidator;
import org.apache.cxf.fediz.service.idp.kerberos.PassThroughKerberosClient;
import org.apache.cxf.ws.security.SecurityConstants;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.wss4j.common.kerberos.KerberosServiceContext;
import org.apache.wss4j.common.principal.SAMLTokenPrincipalImpl;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.dom.WSConstants;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;

/**
 * An authentication provider to authenticate a Kerberos token to the STS
 */
public class STSKrbAuthenticationProvider extends STSAuthenticationProvider {

    private static final Logger LOG = LoggerFactory.getLogger(STSKrbAuthenticationProvider.class);

    private KerberosTokenValidator kerberosTokenValidator;

    private CallbackHandler kerberosCallbackHandler;

    private boolean kerberosUsernameServiceNameForm;

    private boolean requireDelegation;


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // We only handle KerberosServiceRequestTokens
        if (!(authentication instanceof KerberosServiceRequestToken)) {
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

        return handleKerberos((KerberosServiceRequestToken)authentication, sts);
    }

    private Authentication handleKerberos(
        KerberosServiceRequestToken kerberosRequestToken,
        IdpSTSClient sts
    ) {
        Principal kerberosPrincipal = null;
        //
        // If delegation is required then validate the received token + store the
        // Delegated Credential so that we can retrieve a new kerberos token for the
        // STS with it. If delegation is not required, then we just get the received
        // token + pass it to the STS
        //
        if (requireDelegation) {
            kerberosPrincipal = validateKerberosToken(kerberosRequestToken, sts);
            if (kerberosPrincipal == null) {
                return null;
            }
        } else {
            PassThroughKerberosClient kerberosClient = new PassThroughKerberosClient();
            kerberosClient.setToken(kerberosRequestToken.getToken());
            sts.getProperties().put(SecurityConstants.KERBEROS_CLIENT, kerberosClient);
        }

        try {
            // Line below may be uncommented for debugging
            // setTimeout(sts.getClient(), 3600000L);

            SecurityToken token = sts.requestSecurityToken(this.appliesTo);

            if (kerberosPrincipal == null && token.getToken() != null
                && "Assertion".equals(token.getToken().getLocalName())) {
                // For the pass-through Kerberos case, we don't know the Principal name...
                kerberosPrincipal =
                    new SAMLTokenPrincipalImpl(new SamlAssertionWrapper(token.getToken()));
            }

            if (kerberosPrincipal == null) {
                LOG.info("Failed to authenticate user '" + kerberosRequestToken.getName());
                return null;
            }

            List<GrantedAuthority> authorities = createAuthorities(token);

            KerberosServiceRequestToken ksrt =
                new KerberosServiceRequestToken(kerberosPrincipal, authorities, kerberosRequestToken.getToken());

            STSUserDetails details = new STSUserDetails(kerberosPrincipal.getName(),
                                                        "",
                                                        authorities,
                                                        token);
            ksrt.setDetails(details);

            LOG.debug("[IDP_TOKEN={}] provided for user '{}'", token.getId(), kerberosPrincipal.getName());
            return ksrt;
        } catch (Exception ex) {
            LOG.info("Failed to authenticate user '" + kerberosRequestToken.getName() + "'", ex);
            return null;
        }
    }

    private Principal validateKerberosToken(
        KerberosServiceRequestToken token,
        IdpSTSClient sts
    ) {
        if (kerberosTokenValidator == null) {
            LOG.error("KerberosTokenValidator must be configured to support kerberos "
                + "credential delegation");
            return null;
        }
        KerberosServiceContext kerberosContext;
        Principal kerberosPrincipal = null;
        try {
            kerberosContext = kerberosTokenValidator.validate(token);
            if (kerberosContext == null || kerberosContext.getDelegationCredential() == null) {
                LOG.info("Kerberos Validation failure");
                return null;
            }
            GSSCredential delegatedCredential = kerberosContext.getDelegationCredential();
            sts.getProperties().put(SecurityConstants.DELEGATED_CREDENTIAL,
                                    delegatedCredential);
            sts.getProperties().put(SecurityConstants.KERBEROS_USE_CREDENTIAL_DELEGATION, "true");
            kerberosPrincipal = kerberosContext.getPrincipal();
        } catch (LoginException ex) {
            LOG.info("Failed to authenticate user", ex);
            return null;
        } catch (PrivilegedActionException ex) {
            LOG.info("Failed to authenticate user", ex);
            return null;
        }

        if (kerberosTokenValidator.getContextName() != null) {
            sts.getProperties().put(SecurityConstants.KERBEROS_JAAS_CONTEXT_NAME,
                                    kerberosTokenValidator.getContextName());
        }
        if (kerberosTokenValidator.getServiceName() != null) {
            sts.getProperties().put(SecurityConstants.KERBEROS_SPN,
                                    kerberosTokenValidator.getServiceName());
        }
        if (kerberosCallbackHandler != null) {
            sts.getProperties().put(SecurityConstants.CALLBACK_HANDLER,
                                    kerberosCallbackHandler);
        }
        if (kerberosUsernameServiceNameForm) {
            sts.getProperties().put(SecurityConstants.KERBEROS_IS_USERNAME_IN_SERVICENAME_FORM,
                                    "true");
        }

        return kerberosPrincipal;
    }

    protected GSSContext createGSSContext() throws GSSException {
        Oid oid = new Oid("1.2.840.113554.1.2.2");

        GSSManager gssManager = GSSManager.getInstance();

        String spn = "bob@service.ws.apache.org";
        GSSName gssService = gssManager.createName(spn, null);

        return gssManager.createContext(gssService.canonicalize(oid),
                                        oid, null, GSSContext.DEFAULT_LIFETIME);

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(KerberosServiceRequestToken.class);
    }

    public KerberosTokenValidator getKerberosTokenValidator() {
        return kerberosTokenValidator;
    }

    public void setKerberosTokenValidator(KerberosTokenValidator kerberosTokenValidator) {
        this.kerberosTokenValidator = kerberosTokenValidator;
    }

    public CallbackHandler getKerberosCallbackHandler() {
        return kerberosCallbackHandler;
    }

    public void setKerberosCallbackHandler(CallbackHandler kerberosCallbackHandler) {
        this.kerberosCallbackHandler = kerberosCallbackHandler;
    }

    public boolean isKerberosUsernameServiceNameForm() {
        return kerberosUsernameServiceNameForm;
    }

    public void setKerberosUsernameServiceNameForm(boolean kerberosUsernameServiceNameForm) {
        this.kerberosUsernameServiceNameForm = kerberosUsernameServiceNameForm;
    }

    public boolean isRequireDelegation() {
        return requireDelegation;
    }

    public void setRequireDelegation(boolean requireDelegation) {
        this.requireDelegation = requireDelegation;
    }

}
