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

import java.io.IOException;

import org.w3c.dom.Element;
import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.FederationProcessor;
import org.apache.cxf.fediz.core.FederationProcessorImpl;
import org.apache.cxf.fediz.core.FederationRequest;
import org.apache.cxf.fediz.core.FederationResponse;
import org.apache.cxf.fediz.core.config.FederationContext;
import org.apache.cxf.fediz.core.config.jaxb.AudienceUris;
import org.apache.cxf.fediz.core.config.jaxb.CertificateStores;
import org.apache.cxf.fediz.core.config.jaxb.ContextConfig;
import org.apache.cxf.fediz.core.config.jaxb.FederationProtocolType;
import org.apache.cxf.fediz.core.config.jaxb.KeyStoreType;
import org.apache.cxf.fediz.core.config.jaxb.TrustManagersType;
import org.apache.cxf.fediz.core.config.jaxb.TrustedIssuerType;
import org.apache.cxf.fediz.core.config.jaxb.TrustedIssuers;
import org.apache.cxf.fediz.core.config.jaxb.ValidationType;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.exception.ProcessingException.TYPE;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.domain.TrustedIdp;
import org.apache.cxf.fediz.service.idp.util.WebUtils;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.execution.RequestContext;

/**
 * This class is responsible to validate token returned by
 * requestor IDP.
 */

public class ValidateTokenAction {

    private static final String IDP_CONFIG = "idpConfig";
    private static final Logger LOG = LoggerFactory
            .getLogger(ValidateTokenAction.class);

    public SecurityToken submit(RequestContext context)
        throws ProcessingException, IOException {
        Idp idpConfig = (Idp) WebUtils.getAttributeFromFlowScope(
                context, IDP_CONFIG);

        if (idpConfig == null) {
            throw new ProcessingException("IDP configuration is null",
                    TYPE.BAD_REQUEST);
        }

        String whr = (String) WebUtils.getAttributeFromFlowScope(context,
                FederationConstants.PARAM_HOME_REALM);

        if (whr == null) {
            throw new ProcessingException("Home realm is null",
                    TYPE.BAD_REQUEST);
        }

        String wresult = (String) WebUtils.getAttributeFromFlowScope(context,
                FederationConstants.PARAM_RESULT);

        if (wresult == null) {
            throw new ProcessingException("No security token issued",
                    TYPE.BAD_REQUEST);
        }

        TrustedIdp trustedIDPConfig = idpConfig.findTrustedIdp(whr);

        if (trustedIDPConfig == null) {
            throw new ProcessingException(
                    "No trusted IDP config found for home realm " + whr,
                    TYPE.BAD_REQUEST);
        }

        FederationContext fedContext = getFederationContext(idpConfig,
                trustedIDPConfig);

        FederationRequest wfReq = new FederationRequest();
        wfReq.setWa(FederationConstants.ACTION_SIGNIN);
        wfReq.setWresult(wresult);

        FederationProcessor wfProc = new FederationProcessorImpl();
        FederationResponse wfResp = wfProc.processRequest(wfReq, fedContext);

        fedContext.close();

        Element e = wfResp.getToken();
        
        // Create new Security token with new id. 
        // Parameters for freshness computation are copied from original IDP_TOKEN
        String id = IDGenerator.generateID("_");
        SecurityToken idpToken = new SecurityToken(id,
            wfResp.getTokenCreated(), wfResp.getTokenExpires());

        idpToken.setToken(e);
        LOG.info("[IDP_TOKEN=" + id + "] for user '" + wfResp.getUsername()
                + "' created from [RP_TOKEN=" + wfResp.getUniqueTokenId()
                + "] issued by home realm [" + whr + "/"
                + wfResp.getIssuer() + "].");
        if (LOG.isDebugEnabled()) {
            LOG.debug("Created date=" + wfResp.getTokenCreated());
            LOG.debug("Expired date=" + wfResp.getTokenExpires());
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Validated 'wresult' : "
                    + System.getProperty("line.separator") + wresult);
        }
        return idpToken;
    }

    private FederationContext getFederationContext(Idp idpConfig,
            TrustedIdp trustedIdpConfig) throws ProcessingException {

        ContextConfig config = new ContextConfig();

        config.setName("whatever");

        // Configure certificate store
        CertificateStores certStores = new CertificateStores();
        TrustManagersType tm0 = new TrustManagersType();
        KeyStoreType ks0 = new KeyStoreType();
        ks0.setType("PEM");
        // ks0.setType("JKS");
        // ks0.setPassword("changeit");
        ks0.setFile(trustedIdpConfig.getCertificate());
        tm0.setKeyStore(ks0);
        certStores.getTrustManager().add(tm0);
        config.setCertificateStores(certStores);

        // Configure trusted IDP
        TrustedIssuers trustedIssuers = new TrustedIssuers();
        TrustedIssuerType ti0 = new TrustedIssuerType();
        ti0.setCertificateValidation(ValidationType.PEER_TRUST);
        ti0.setName(trustedIdpConfig.getName());
        // ti0.setSubject(".*CN=www.sts.com.*");
        trustedIssuers.getIssuer().add(ti0);
        config.setTrustedIssuers(trustedIssuers);

        FederationProtocolType protocol = new FederationProtocolType();
        config.setProtocol(protocol);

        AudienceUris audienceUris = new AudienceUris();
        audienceUris.getAudienceItem().add(idpConfig.getRealm());
        config.setAudienceUris(audienceUris);

        FederationContext fedContext = new FederationContext(config);
        fedContext.init();
        return fedContext;
    }

}
