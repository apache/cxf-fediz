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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.xml.namespace.QName;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.binding.soap.SoapFault;
import org.apache.cxf.fediz.core.FederationConstants;
import org.apache.cxf.fediz.core.exception.ProcessingException;
import org.apache.cxf.fediz.core.exception.ProcessingException.TYPE;
import org.apache.cxf.fediz.core.util.DOMUtils;
import org.apache.cxf.fediz.service.idp.IdpSTSClient;
import org.apache.cxf.fediz.service.idp.domain.Application;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.domain.RequestClaim;
import org.apache.cxf.fediz.service.idp.util.WebUtils;
import org.apache.cxf.staxutils.StaxUtils;
import org.apache.cxf.staxutils.W3CDOMStreamWriter;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.cxf.ws.security.trust.STSClient;
import org.apache.cxf.ws.security.trust.STSUtils;
import org.apache.wss4j.dom.WSConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.execution.RequestContext;

/**
 * This class is responsible to ask for Security Tokens to STS.
 */

public class STSClientAction {

    private static final String HTTP_SCHEMAS_XMLSOAP_ORG_WS_2005_05_IDENTITY = 
            "http://schemas.xmlsoap.org/ws/2005/05/identity";

    private static final String HTTP_DOCS_OASIS_OPEN_ORG_WS_SX_WS_TRUST_200512_BEARER = 
            "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer";
    
    private static final String HTTP_DOCS_OASIS_OPEN_ORG_WS_SX_WS_TRUST_200512_PUBLICKEY = 
            "http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey";

    private static final String HTTP_WWW_W3_ORG_2005_08_ADDRESSING = "http://www.w3.org/2005/08/addressing";

    private static final String HTTP_DOCS_OASIS_OPEN_ORG_WS_SX_WS_TRUST_200512 = 
            "http://docs.oasis-open.org/ws-sx/ws-trust/200512/";
    
    private static final String HTTP_SCHEMAS_XMLSOAP_ORG_WS_2005_02_TRUST =
        "http://schemas.xmlsoap.org/ws/2005/02/trust";

    private static final String SECURITY_TOKEN_SERVICE = "SecurityTokenService";

    private static final Logger LOG = LoggerFactory
            .getLogger(STSClientAction.class);
    
    protected String namespace = HTTP_DOCS_OASIS_OPEN_ORG_WS_SX_WS_TRUST_200512;

    protected String wsdlLocation;

    protected String wsdlEndpoint;
    
    protected String wsdlService = SECURITY_TOKEN_SERVICE;
  
    protected String tokenType = WSConstants.WSS_SAML2_TOKEN_TYPE;
    
    protected boolean use200502Namespace;
    
    protected int ttl = 1800;
    
    protected Bus bus;
    
    private boolean isPortSet;
    
    private String keyType = HTTP_DOCS_OASIS_OPEN_ORG_WS_SX_WS_TRUST_200512_BEARER;

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
    
    public String getWsdlService() {
        return wsdlService;
    }

    public void setWsdlService(String wsdlService) {
        this.wsdlService = wsdlService;
    }
    
    public String getNamespace() {
        return namespace;
    }

    public void setNamespace(String namespace) {
        this.namespace = namespace;
    }
    
    public void setBus(Bus bus) {
        this.bus = bus;
    }

    public Bus getBus() {
        // do not store a referance to the default bus
        return (bus != null) ? bus : BusFactory.getDefaultBus();
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public int getTtl() {
        return ttl;
    }

    public void setTtl(int ttl) {
        this.ttl = ttl;
    }
    
    /**
     * @param context the webflow request context
     * @param realm The client/application realm
     * @return a serialized RP security token
     * @throws Exception
     */
    public String submit(RequestContext context, String realm)
        throws Exception {
        
        SecurityToken idpToken = getSecurityToken(context);

        Bus cxfBus = getBus();
        Idp idpConfig = (Idp) WebUtils.getAttributeFromFlowScope(context, "idpConfig");

        IdpSTSClient sts = new IdpSTSClient(cxfBus);
        sts.setAddressingNamespace(HTTP_WWW_W3_ORG_2005_08_ADDRESSING);
        
        Application serviceConfig = idpConfig.findApplication(realm);
        if (serviceConfig == null) {
            LOG.warn("No service config found for " + realm);
            throw new ProcessingException(TYPE.BAD_REQUEST);
        }
        
        // Parse wreq parameter - we only support parsing TokenType and KeyType for now
        String wreq = (String)WebUtils.getAttributeFromFlowScope(context, FederationConstants.PARAM_REQUEST);
        String stsTokenType = null;
        String stsKeyType = keyType;
        if (wreq != null) {
            try {
                Document wreqDoc = DOMUtils.readXml(new StringReader(wreq));
                Element wreqElement = wreqDoc.getDocumentElement();
                if (wreqElement != null && "RequestSecurityToken".equals(wreqElement.getLocalName())
                    && (STSUtils.WST_NS_05_12.equals(wreqElement.getNamespaceURI())
                        || HTTP_SCHEMAS_XMLSOAP_ORG_WS_2005_02_TRUST.equals(wreqElement.getNamespaceURI()))) {
                    Element tokenTypeElement = 
                        DOMUtils.getFirstChildWithName(wreqElement, wreqElement.getNamespaceURI(), "TokenType");
                    if (tokenTypeElement != null) {
                        stsTokenType = tokenTypeElement.getTextContent();
                    }
                    Element keyTypeElement = 
                        DOMUtils.getFirstChildWithName(wreqElement, wreqElement.getNamespaceURI(), "KeyType");
                    if (keyTypeElement != null) {
                        stsKeyType = keyTypeElement.getTextContent();
                    }
                }
            } catch (Exception e) {
                LOG.warn("Error parsing 'wreq' parameter: " + e.getMessage());
                throw new ProcessingException(TYPE.BAD_REQUEST);
            }
        }
        
        if (stsTokenType != null) {
            sts.setTokenType(stsTokenType);
        } else if (serviceConfig.getTokenType() != null && serviceConfig.getTokenType().length() > 0) {
            sts.setTokenType(serviceConfig.getTokenType());
        } else {
            sts.setTokenType(getTokenType());
        }
        
        if (serviceConfig.getPolicyNamespace() != null && serviceConfig.getPolicyNamespace().length() > 0) {
            sts.setWspNamespace(serviceConfig.getPolicyNamespace());
        }
        
        LOG.debug("TokenType {} set for realm {}", sts.getTokenType(), realm);
        
        sts.setKeyType(stsKeyType);
        if (HTTP_DOCS_OASIS_OPEN_ORG_WS_SX_WS_TRUST_200512_PUBLICKEY.equals(stsKeyType)) {
            HttpServletRequest servletRequest = WebUtils.getHttpServletRequest(context);
            if (servletRequest != null) {
                X509Certificate certs[] = 
                    (X509Certificate[])servletRequest.getAttribute("javax.servlet.request.X509Certificate");
                if (certs != null && certs.length > 0) {
                    sts.setUseCertificateForConfirmationKeyInfo(true);
                    sts.setUseKeyCertificate(certs[0]);
                } else {
                    LOG.info("Can't send a PublicKey KeyType as no client certs are available");
                    sts.setKeyType(HTTP_DOCS_OASIS_OPEN_ORG_WS_SX_WS_TRUST_200512_BEARER);
                }
            }
        }

        processWsdlLocation(context);
        sts.setWsdlLocation(wsdlLocation);
        sts.setServiceQName(new QName(namespace, wsdlService));
        sts.setEndpointQName(new QName(namespace, wsdlEndpoint));
        if (use200502Namespace) {
            sts.setNamespace(HTTP_SCHEMAS_XMLSOAP_ORG_WS_2005_02_TRUST);
        }

        if (serviceConfig.getRequestedClaims() != null && serviceConfig.getRequestedClaims().size() > 0) {
            addClaims(sts, serviceConfig.getRequestedClaims());
            LOG.debug("Requested claims set for {}", realm);
        }
        
        sts.setEnableLifetime(true);
        setLifetime(sts, serviceConfig, realm);
        
        sts.setOnBehalfOf(idpToken.getToken());
        if (!(serviceConfig.getProtocol() == null
            || FederationConstants.WS_FEDERATION_NS.equals(serviceConfig.getProtocol()))) {
            LOG.error("Protocol {} not supported for realm {} ", serviceConfig.getProtocol(), realm);
            throw new ProcessingException(TYPE.BAD_REQUEST);
        }
        
        String rpToken = null;
        try {
            rpToken = sts.requestSecurityTokenResponse(realm);
        } catch (SoapFault ex) {
            LOG.error("Error in retrieving a token", ex.getMessage());
            if (ex.getFaultCode() != null 
                && "RequestFailed".equals(ex.getFaultCode().getLocalPart())) {
                throw new ProcessingException(TYPE.BAD_REQUEST);
            }
            throw ex;
        }

        if (LOG.isInfoEnabled()) {
            String id = getIdFromToken(rpToken);
            
            LOG.info("[RP_TOKEN={}] successfully created for realm [{}] on behalf of [IDP_TOKEN={}]",
                     id, realm, idpToken.getId());
        }
        return StringEscapeUtils.escapeXml11(rpToken);
    }
    
    private String getIdFromToken(String token) throws IOException, XMLStreamException {
        Document doc = null;
        try (InputStream is = new ByteArrayInputStream(token.getBytes())) {
            doc = StaxUtils.read(is);
        }
        NodeList nd = doc.getElementsByTagNameNS(WSConstants.SAML2_NS, "Assertion");
        
        String identifier = "ID";
        if (nd.getLength() == 0) {
            nd = doc.getElementsByTagNameNS(WSConstants.SAML_NS, "Assertion");
            identifier = "AssertionID";
        }
        
        if (nd.getLength() > 0) {
            Element e = (Element) nd.item(0);
            if (e.hasAttributeNS(null, identifier)) {
                return e.getAttributeNS(null, identifier);
            }
        }
        
        return "";
    }

    private SecurityToken getSecurityToken(RequestContext context) throws ProcessingException {
        String whr = (String) WebUtils.
            getAttributeFromFlowScope(context, FederationConstants.PARAM_HOME_REALM);

        SecurityToken idpToken = (SecurityToken) WebUtils.getAttributeFromFlowScope(context, "idpToken");
        if (idpToken != null) {
            LOG.debug("[IDP_TOKEN={} successfully retrieved from cache for home realm [{}]",
                          idpToken.getId(), whr);
        } else {
            LOG.error("IDP_TOKEN not found");
            throw new ProcessingException(TYPE.BAD_REQUEST);
        }
        return idpToken;
    }
    

    private void processWsdlLocation(RequestContext context) {
        if (!isPortSet) {
            try {
                URL url = new URL(this.wsdlLocation);
                URL updatedUrl = new URL(url.getProtocol(), url.getHost(),
                                         WebUtils.getHttpServletRequest(context).getLocalPort(), url.getFile());
                
                setSTSWsdlUrl(updatedUrl.toString());
                LOG.info("STS WSDL URL updated to {}", updatedUrl.toString());
            } catch (MalformedURLException e) {
                LOG.error("Invalid Url '{}': {}", this.wsdlLocation, e.getMessage());
            }
        }
    }

    private void addClaims(STSClient sts, List<RequestClaim> requestClaimList)
        throws ParserConfigurationException, XMLStreamException {
        
        Element claims = createClaimsElement(requestClaimList);
        if (claims != null) {
            sts.setClaims(claims);
        }
    }

    private Element createClaimsElement(List<RequestClaim> realmClaims)
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
            for (RequestClaim item : realmClaims) {
                LOG.debug("  {}", item.getClaimType().toString());
                writer.writeStartElement("ic", "ClaimType",
                        HTTP_SCHEMAS_XMLSOAP_ORG_WS_2005_05_IDENTITY);
                writer.writeAttribute("Uri", item.getClaimType().toString());
                writer.writeAttribute("Optional", Boolean.toString(item.isOptional())); 
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

    public String getKeyType() {
        return keyType;
    }

    public void setKeyType(String keyType) {
        this.keyType = keyType;
    }

    public boolean isUse200502Namespace() {
        return use200502Namespace;
    }

    public void setUse200502Namespace(boolean use200502Namespace) {
        this.use200502Namespace = use200502Namespace;
    }

    private void setLifetime(STSClient sts, Application serviceConfig, String wtrealm) {
        if (serviceConfig.getLifeTime() > 0) {
            try {
                int lifetime = serviceConfig.getLifeTime();
                sts.setTtl(lifetime);
                sts.setEnableLifetime(lifetime > 0);
                LOG.debug("Lifetime set to {} seconds for realm {}", serviceConfig.getLifeTime(), wtrealm);
            } catch (NumberFormatException ex) {
                LOG.warn("Invalid lifetime configured for service provider " + wtrealm);
                sts.setTtl(this.ttl);
                sts.setEnableLifetime(this.ttl > 0);
            }
        } else {
            sts.setTtl(this.ttl);
            sts.setEnableLifetime(this.ttl > 0);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Lifetime set to {} seconds for realm {}", this.ttl, wtrealm);
            }
        }
    }
}
