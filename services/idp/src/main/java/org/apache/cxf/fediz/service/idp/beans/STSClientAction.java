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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamException;

import org.w3c.dom.Element;

import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.fediz.service.idp.IdpSTSClient;
import org.apache.cxf.fediz.service.idp.UsernamePasswordCredentials;
import org.apache.cxf.fediz.service.idp.util.WebUtils;
import org.apache.cxf.staxutils.W3CDOMStreamWriter;
import org.apache.cxf.ws.security.SecurityConstants;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.cxf.ws.security.trust.STSUtils;
import org.apache.ws.security.WSConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.webflow.execution.RequestContext;

/**
 * @author fr17993 
This class is responsible to ask for Security Tokens to STS.
 */

public class STSClientAction {

    private static final String REALM_TO_CLAIMS_MAP = "realm2ClaimsMap";

    private static final String HTTP_SCHEMAS_XMLSOAP_ORG_WS_2005_05_IDENTITY = 
            "http://schemas.xmlsoap.org/ws/2005/05/identity";

    private static final String HTTP_DOCS_OASIS_OPEN_ORG_WS_SX_WS_TRUST_200512_BEARER = 
            "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer";

    private static final String HTTP_WWW_W3_ORG_2005_08_ADDRESSING = "http://www.w3.org/2005/08/addressing";

    private static final String HTTP_DOCS_OASIS_OPEN_ORG_WS_SX_WS_TRUST_200512 = 
            "http://docs.oasis-open.org/ws-sx/ws-trust/200512/";

    private static final String SECURITY_TOKEN_SERVICE = "SecurityTokenService";

    private static final Logger LOG = LoggerFactory
            .getLogger(STSClientAction.class);

    protected String wsdlLocation;

    protected String wsdlEndpoint;

    protected String appliesTo;

    protected String tokenType;

    protected boolean claimsRequired = true;
    
    protected boolean isPortSet;

    public String getWsdlLocation() {
        return wsdlLocation;
    }

    public void setWsdlLocation(String wsdlLocation) {
        this.wsdlLocation = wsdlLocation;
        try {
            URL url = new URL(wsdlLocation);
            isPortSet = url.getPort() > 0;
            if (!isPortSet) {
                LOG.info("Port is 0 for 'wsdlLocation'. Port evaluated when processing first request.");
            }
        } catch (MalformedURLException e) {
            LOG.error("Invalid Url '" + wsdlLocation + "': "  + e.getMessage());
        }
    }

    public String getWsdlEndpoint() {
        return wsdlEndpoint;
    }

    public void setWsdlEndpoint(String wsdlEndpoint) {
        this.wsdlEndpoint = wsdlEndpoint;
    }

    public String getAppliesTo() {
        return appliesTo;
    }

    public void setAppliesTo(String appliesTo) {
        this.appliesTo = appliesTo;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public boolean isClaimsRequired() {
        return claimsRequired;
    }

    public void setClaimsRequired(boolean claimsRequired) {
        this.claimsRequired = claimsRequired;
    }

    /**
     * @param credentials
     *            : username and password provided by user
     * @return a IDP {@link SecurityToken}
     * @throws Exception
     */
    public SecurityToken submit(UsernamePasswordCredentials credentials, RequestContext context)
        throws Exception {

        Bus bus = BusFactory.getDefaultBus();

        IdpSTSClient sts = new IdpSTSClient(bus);
        sts.setAddressingNamespace(HTTP_WWW_W3_ORG_2005_08_ADDRESSING);
        paramTokenType(sts);
        sts.setKeyType(HTTP_DOCS_OASIS_OPEN_ORG_WS_SX_WS_TRUST_200512_BEARER);

        if (!isPortSet) {
            try {
                URL url = new URL(this.wsdlLocation);
                URL updatedUrl = new URL(url.getProtocol(), url.getHost(),
                                         WebUtils.getHttpServletRequest(context).getLocalPort(), url.getFile());
                
                setSTSWsdlUrl(updatedUrl.toString());
                LOG.info("STS WSDL URL updated to " + updatedUrl.toString());
            } catch (MalformedURLException e) {
                LOG.error("Invalid Url '" + this.wsdlLocation + "': "  + e.getMessage());
            }
        }
        sts.setWsdlLocation(this.wsdlLocation);
        sts.setServiceQName(new QName(
                HTTP_DOCS_OASIS_OPEN_ORG_WS_SX_WS_TRUST_200512,
                SECURITY_TOKEN_SERVICE));
        sts.setEndpointQName(new QName(
                HTTP_DOCS_OASIS_OPEN_ORG_WS_SX_WS_TRUST_200512,
                this.wsdlEndpoint));

        if (this.claimsRequired) {
            addClaims(this.appliesTo, bus, sts);
        }

        sts.getProperties().put(SecurityConstants.USERNAME,
                credentials.getUsername());
        sts.getProperties().put(SecurityConstants.PASSWORD,
                credentials.getPassword());

        SecurityToken idpToken = sts.requestSecurityToken(this.appliesTo);

        LOG.info("Token [IDP_TOKEN] produced succesfully.");
        return idpToken;
    }

    /**
     * @param credentials
     *            {@link SecurityToken}
     * @param wtrealm
     *            the relying party security domain
     * @return a serialized RP security token
     * @throws Exception
     */
    public String submit(SecurityToken credentials, String wtrealm)
        throws Exception {

        Bus bus = BusFactory.getDefaultBus();

        IdpSTSClient sts = new IdpSTSClient(bus);
        sts.setAddressingNamespace(HTTP_WWW_W3_ORG_2005_08_ADDRESSING);
        paramTokenType(sts);
        sts.setKeyType(HTTP_DOCS_OASIS_OPEN_ORG_WS_SX_WS_TRUST_200512_BEARER);

        sts.setWsdlLocation(wsdlLocation);
        sts.setServiceQName(new QName(
                HTTP_DOCS_OASIS_OPEN_ORG_WS_SX_WS_TRUST_200512,
                SECURITY_TOKEN_SERVICE));
        sts.setEndpointQName(new QName(
                HTTP_DOCS_OASIS_OPEN_ORG_WS_SX_WS_TRUST_200512, wsdlEndpoint));

        if (this.claimsRequired) {
            addClaims(wtrealm, bus, sts);
        }

        sts.setOnBehalfOf(credentials.getToken());

        String rpToken = sts.requestSecurityTokenResponse(wtrealm);

        LOG.info("Token [RP_TOKEN] produced succesfully.");
        return StringEscapeUtils.escapeXml(rpToken);
    }

    private void addClaims(String wtrealm, Bus bus, IdpSTSClient sts)
        throws ParserConfigurationException, XMLStreamException {
        List<String> realmClaims = null;
        ApplicationContext ctx = (ApplicationContext) bus
                .getExtension(ApplicationContext.class);

        @SuppressWarnings("unchecked")
        Map<String, List<String>> realmClaimsMap = (Map<String, List<String>>) ctx
                .getBean(REALM_TO_CLAIMS_MAP);
        realmClaims = realmClaimsMap.get(wtrealm);
        if (realmClaims != null && realmClaims.size() > 0
                && LOG.isDebugEnabled()) {
            LOG.debug("claims for realm " + wtrealm);
            for (String item : realmClaims) {
                LOG.debug("  " + item);
            }
        }
        Element claims = createClaimsElement(realmClaims);
        if (claims != null) {
            sts.setClaims(claims);
        }
    }

    private void paramTokenType(IdpSTSClient sts) {
        if (tokenType == null) {
            sts.setTokenType(WSConstants.WSS_SAML2_TOKEN_TYPE);
        } else {
            sts.setTokenType(tokenType);
        }
    }

    private Element createClaimsElement(List<String> realmClaims)
        throws ParserConfigurationException, XMLStreamException {
        if (realmClaims == null || realmClaims.size() == 0) {
            return null;
        }

        W3CDOMStreamWriter writer = new W3CDOMStreamWriter();
        writer.writeStartElement("wst", "Claims", STSUtils.WST_NS_05_12);
        writer.writeNamespace("wst", STSUtils.WST_NS_05_12);
        writer.writeNamespace("ic",
                HTTP_SCHEMAS_XMLSOAP_ORG_WS_2005_05_IDENTITY);
        writer.writeAttribute("Dialect",
                HTTP_SCHEMAS_XMLSOAP_ORG_WS_2005_05_IDENTITY);

        if (realmClaims != null && realmClaims.size() > 0) {
            for (String item : realmClaims) {
                LOG.debug("claim: " + item);
                writer.writeStartElement("ic", "ClaimType",
                        HTTP_SCHEMAS_XMLSOAP_ORG_WS_2005_05_IDENTITY);
                writer.writeAttribute("Uri", item);
                writer.writeEndElement();
            }
        }

        writer.writeEndElement();

        return writer.getDocument().getDocumentElement();
    }
    
    private synchronized void setSTSWsdlUrl(String wsdlUrl) {
        this.wsdlLocation = wsdlUrl;
        this.isPortSet = true;
    }
}
