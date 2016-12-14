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
package org.apache.cxf.fediz.service.idp.beans;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.service.idp.IdpConstants;
import org.apache.cxf.fediz.service.idp.domain.Application;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.samlsso.SAMLAuthnRequest;
import org.apache.cxf.fediz.service.idp.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.RequestContext;

@Component
public class SigninParametersCacheAction {

    public static final String ACTIVE_APPLICATIONS = "realmConfigMap";

    private static final Logger LOG = LoggerFactory.getLogger(SigninParametersCacheAction.class);

    public void store(RequestContext context, String protocol) {
        Map<String, Object> signinParams = new HashMap<>();
        String uuidKey = UUID.randomUUID().toString();

        Object value = WebUtils.getAttributeFromFlowScope(context, IdpConstants.HOME_REALM);
        if (value != null) {
            signinParams.put(IdpConstants.HOME_REALM, value);
        }
        value = WebUtils.getAttributeFromFlowScope(context, IdpConstants.CONTEXT);
        if (value != null) {
            signinParams.put(IdpConstants.CONTEXT, value);
        }

        if ("wsfed".equals(protocol)) {
            value = WebUtils.getAttributeFromFlowScope(context, IdpConstants.RETURN_ADDRESS);
            if (value != null) {
                signinParams.put(FederationConstants.PARAM_REPLY, value);
            }
            value = WebUtils.getAttributeFromFlowScope(context, IdpConstants.REALM);
            if (value != null) {
                signinParams.put(IdpConstants.REALM, value);
            }
        } else if ("samlsso".equals(protocol)) {
            value = WebUtils.getAttributeFromFlowScope(context, IdpConstants.SAML_AUTHN_REQUEST);
            if (value != null) {
                signinParams.put(IdpConstants.SAML_AUTHN_REQUEST, value);
            }
        }

        WebUtils.putAttributeInExternalContext(context, uuidKey, signinParams);

        LOG.debug("SignIn parameters cached: {}", signinParams.toString());
        WebUtils.putAttributeInFlowScope(context, IdpConstants.TRUSTED_IDP_CONTEXT, uuidKey);
        LOG.info("SignIn parameters cached and context set to [" + uuidKey + "].");
    }

    public void restore(RequestContext context, String contextKey, String protocol) {

        if (contextKey != null) {
            @SuppressWarnings("unchecked")
            Map<String, Object> signinParams =
                (Map<String, Object>)WebUtils.getAttributeFromExternalContext(context, contextKey);

            if (signinParams != null) {
                LOG.debug("SignIn parameters restored: {}", signinParams.toString());

                String value = (String)signinParams.get(IdpConstants.HOME_REALM);
                if (value != null) {
                    WebUtils.putAttributeInFlowScope(context, IdpConstants.HOME_REALM, value);
                }
                value = (String)signinParams.get(IdpConstants.REALM);
                if (value != null) {
                    WebUtils.putAttributeInFlowScope(context, IdpConstants.REALM, value);
                }

                if ("wsfed".equals(protocol)) {
                    value = (String)signinParams.get(FederationConstants.PARAM_REPLY);
                    if (value != null) {
                        WebUtils.putAttributeInFlowScope(context, FederationConstants.PARAM_REPLY, value);
                    }

                    WebUtils.removeAttributeFromFlowScope(context, FederationConstants.PARAM_CONTEXT);
                    LOG.info("SignIn parameters restored and " + FederationConstants.PARAM_CONTEXT + "["
                        + contextKey + "] cleared.");

                } else if ("samlsso".equals(protocol)) {
                    SAMLAuthnRequest authnRequest =
                        (SAMLAuthnRequest)signinParams.get(IdpConstants.SAML_AUTHN_REQUEST);
                    if (authnRequest != null) {
                        WebUtils.putAttributeInFlowScope(context, IdpConstants.SAML_AUTHN_REQUEST, authnRequest);
                    }
                }

                value = (String)signinParams.get(IdpConstants.CONTEXT);
                if (value != null) {
                    WebUtils.putAttributeInFlowScope(context, IdpConstants.CONTEXT, value);
                }

            }  else {
                LOG.debug("Error in restoring security context");
            }

            WebUtils.removeAttributeFromFlowScope(context, contextKey);
        } else {
            LOG.debug("Error in restoring security context");
        }
    }

    public void storeRPConfigInSession(RequestContext context) throws ProcessingException {

        String wtrealm = (String)WebUtils.getAttributeFromFlowScope(context, FederationConstants.PARAM_TREALM);
        Idp idpConfig = (Idp) WebUtils.getAttributeFromFlowScope(context, IdpConstants.IDP_CONFIG);
        if (wtrealm == null || idpConfig == null) {
            return;
        }

        Application serviceConfig = idpConfig.findApplication(wtrealm);
        if (serviceConfig != null) {
            if (serviceConfig.getPassiveRequestorEndpoint() == null) {
                String url = guessPassiveRequestorURL(context, wtrealm);
                serviceConfig.setPassiveRequestorEndpoint(url);
            }

            @SuppressWarnings("unchecked")
            Map<String, Application> realmConfigMap =
                    (Map<String, Application>)WebUtils
                            .getAttributeFromExternalContext(context, ACTIVE_APPLICATIONS);

            if (realmConfigMap == null) {
                realmConfigMap = new HashMap<>();
                WebUtils.putAttributeInExternalContext(context, ACTIVE_APPLICATIONS, realmConfigMap);
            }

            if (realmConfigMap.get(wtrealm) == null) {
                realmConfigMap.put(wtrealm, serviceConfig);
            }
        }
    }

    protected String guessPassiveRequestorURL(RequestContext context, String wtrealm) throws ProcessingException {
        String url = (String)WebUtils.getAttributeFromFlowScope(context, FederationConstants.PARAM_REPLY);
        try {
            //basic check if the url is correctly formed
            new URL(url);
        } catch (Exception e) {
            url = null;
        }
        if (url == null) {
            url = wtrealm;
            try {
                //basic check if the url is correctly formed
                new URL(url);
            } catch (Exception e) {
                throw new ProcessingException(e.getMessage(), e, ProcessingException.TYPE.INVALID_REQUEST);
            }
        }
        return url;
    }
}
