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

package org.apache.cxf.fediz.service.idp.protocols;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.cxf.fediz.core.util.CertsUtils;
import org.apache.cxf.fediz.service.idp.IdpConstants;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.domain.TrustedIdp;
import org.apache.cxf.jaxrs.json.basic.JsonMapObject;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.bean.AttributeStatementBean;
import org.apache.wss4j.common.saml.bean.ConditionsBean;
import org.apache.wss4j.common.saml.bean.SubjectBean;
import org.apache.wss4j.common.saml.bean.Version;
import org.apache.wss4j.common.saml.builder.SAML2Constants;
import org.apache.wss4j.common.util.Loader;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.execution.RequestContext;

public abstract class AbstractTrustedIdpOAuth2ProtocolHandler extends AbstractTrustedIdpProtocolHandler {

    /**
     * The client_id value to send to the IdP.
     */
    public static final String CLIENT_ID = "client.id";

    /**
     * The secret associated with the client to authenticate to the IdP.
     */
    public static final String CLIENT_SECRET = "client.secret";

    /**
     * The Token endpoint. The authorization endpoint is specified by TrustedIdp.url.
     */
    public static final String TOKEN_ENDPOINT = "token.endpoint";

    /**
     * Additional (space-separated) parameters to be sent in the "scope" to the authorization endpoint.
     * The default value depends on the subclass.
     */
    public static final String SCOPE = "scope";

    /**
     * The fully qualified class name of a ClaimsHandler implementation, designed to convert claims in a JWT token
     * into claims in the generated SAML token.
     */
    public static final String CLAIMS_HANDLER = "claims.handler";

    private static final Logger LOG = LoggerFactory.getLogger(AbstractTrustedIdpOAuth2ProtocolHandler.class);

    @Override
    public URL mapSignInRequest(RequestContext context, Idp idp, TrustedIdp trustedIdp) {

        String clientId = getProperty(trustedIdp, CLIENT_ID);
        if (clientId == null || clientId.isEmpty()) {
            LOG.warn("A CLIENT_ID must be configured for OAuth 2.0");
            throw new IllegalStateException("No CLIENT_ID specified");
        }

        String scope = getScope(trustedIdp);
        LOG.debug("Using scope: {}", scope);

        try {
            final String url = trustedIdp.getUrl()
                    + "?response_type=code"
                    + "&client_id=" + clientId
                    + "&redirect_uri=" + URLEncoder.encode(idp.getIdpUrl().toString(), "UTF-8")
                    + "&scope=" + URLEncoder.encode(scope, "UTF-8")
                    + "&state=" + context.getFlowScope().getString(IdpConstants.TRUSTED_IDP_CONTEXT);
            return new URL(url);
        } catch (MalformedURLException ex) {
            LOG.error("Invalid Redirect URL for Trusted Idp", ex);
            throw new IllegalStateException("Invalid Redirect URL for Trusted Idp");
        } catch (UnsupportedEncodingException ex) {
            LOG.error("Invalid Redirect URL for Trusted Idp", ex);
            throw new IllegalStateException("Invalid Redirect URL for Trusted Idp");
        }
    }

    protected SamlAssertionWrapper createSamlAssertion(Idp idp, TrustedIdp trustedIdp, JsonMapObject claims, 
                                                     String subjectName,
                                                     Instant notBefore,
                                                     Instant expires) throws Exception {
        SamlCallbackHandler callbackHandler = new SamlCallbackHandler();
        String issuer = idp.getServiceDisplayName();
        if (issuer == null) {
            issuer = idp.getRealm();
        }
        if (issuer != null) {
            callbackHandler.setIssuer(issuer);
        }

        // Subject
        SubjectBean subjectBean =
            new SubjectBean(subjectName, SAML2Constants.NAMEID_FORMAT_UNSPECIFIED, SAML2Constants.CONF_BEARER);
        callbackHandler.setSubjectBean(subjectBean);

        // Conditions
        ConditionsBean conditionsBean = new ConditionsBean();
        conditionsBean.setNotAfter(new DateTime(Date.from(expires)));
        if (notBefore != null) {
            DateTime notBeforeDT = new DateTime(Date.from(notBefore));
            conditionsBean.setNotBefore(notBeforeDT);
        } else {
            conditionsBean.setNotBefore(new DateTime());
        }
        callbackHandler.setConditionsBean(conditionsBean);

        // Claims
        String claimsHandler = getProperty(trustedIdp, CLAIMS_HANDLER);
        if (claimsHandler != null) {
            ClaimsHandler claimsHandlerImpl = (ClaimsHandler)Loader.loadClass(claimsHandler).newInstance();
            AttributeStatementBean attrStatementBean = claimsHandlerImpl.handleClaims(claims);
            callbackHandler.setAttrBean(attrStatementBean);
        }

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);

        SamlAssertionWrapper assertion = new SamlAssertionWrapper(samlCallback);

        Crypto crypto = CertsUtils.getCryptoFromCertificate(idp.getCertificate());
        assertion.signAssertion(crypto.getDefaultX509Identifier(), idp.getCertificatePassword(),
                                crypto, false);

        return assertion;
    }

    private static class SamlCallbackHandler implements CallbackHandler {
        private ConditionsBean conditionsBean;
        private SubjectBean subjectBean;
        private String issuer;
        private AttributeStatementBean attrBean;

        /**
         * Set the SubjectBean
         */
        public void setSubjectBean(SubjectBean subjectBean) {
            this.subjectBean = subjectBean;
        }

        /**
         * Set the ConditionsBean
         */
        public void setConditionsBean(ConditionsBean conditionsBean) {
            this.conditionsBean = conditionsBean;
        }

        /**
         * Set the issuer name
         */
        public void setIssuer(String issuerName) {
            this.issuer = issuerName;
        }

        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof SAMLCallback) {
                    SAMLCallback samlCallback = (SAMLCallback) callback;

                    // Set the Subject
                    if (subjectBean != null) {
                        samlCallback.setSubject(subjectBean);
                    }
                    samlCallback.setSamlVersion(Version.SAML_20);

                    // Set the issuer
                    samlCallback.setIssuer(issuer);

                    // Set the conditions
                    samlCallback.setConditions(conditionsBean);

                    // Set the attributes
                    if (attrBean != null) {
                        samlCallback.setAttributeStatementData(Collections.singletonList(attrBean));
                    }
                }
            }
        }

        public void setAttrBean(AttributeStatementBean attrBean) {
            this.attrBean = attrBean;
        }

    }

    abstract String getScope(TrustedIdp trustedIdp);

}
