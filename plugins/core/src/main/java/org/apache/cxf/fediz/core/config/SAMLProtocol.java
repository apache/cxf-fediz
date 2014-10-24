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

package org.apache.cxf.fediz.core.config;

import org.apache.cxf.fediz.core.config.jaxb.ProtocolType;
import org.apache.cxf.fediz.core.config.jaxb.SamlProtocolType;
import org.apache.cxf.fediz.core.saml.SAMLTokenValidator;
import org.apache.cxf.fediz.core.samlsso.DefaultSAMLPRequestBuilder;
import org.apache.cxf.fediz.core.samlsso.SAMLPRequestBuilder;
import org.apache.wss4j.common.util.Loader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SAMLProtocol extends Protocol {

    private static final Logger LOG = LoggerFactory.getLogger(SAMLProtocol.class);
    
    private SAMLPRequestBuilder samlpRequestBuilder;
    
    public SAMLProtocol(ProtocolType protocolType) {
        super(protocolType);
        
        // add SAMLTokenValidator as the last one
        // Fediz chooses the first validator in the list if its
        // canHandleToken or canHandleTokenType method return true
        SAMLTokenValidator validator = new SAMLTokenValidator();
        getTokenValidators().add(getTokenValidators().size(), validator);
    }
    
    protected SamlProtocolType getSAMLProtocol() {
        return (SamlProtocolType)super.getProtocolType();
    }

    protected void setSAMLProtocol(SamlProtocolType samlProtocol) {
        super.setProtocolType(samlProtocol);
    }

    public boolean isSignRequest() {
        return getSAMLProtocol().isSignRequest();
    }

    public void setSignRequest(boolean signRequest) {
        getSAMLProtocol().setSignRequest(signRequest);
    }
    
    public SAMLPRequestBuilder getSAMLPRequestBuilder() {
        if (samlpRequestBuilder != null) {
            return samlpRequestBuilder;
        }
        
        // See if we have a custom SAMLPRequestBuilder
        String samlpRequestBuilderStr = getSAMLProtocol().getAuthnRequestBuilder();
        if (samlpRequestBuilderStr != null && !"".equals(samlpRequestBuilderStr)) {
            try {
                Class<?> samlpRequestBuilderClass = Loader.loadClass(samlpRequestBuilderStr);
                samlpRequestBuilder = (SAMLPRequestBuilder) samlpRequestBuilderClass.newInstance();
            } catch (ClassNotFoundException ex) {
                LOG.debug(ex.getMessage(), ex);
            } catch (InstantiationException ex) {
                LOG.debug(ex.getMessage(), ex);
            } catch (IllegalAccessException ex) {
                LOG.debug(ex.getMessage(), ex);
            }
        }
        
        // Default implementation
        samlpRequestBuilder = new DefaultSAMLPRequestBuilder();
        
        return samlpRequestBuilder;
    }

    public void setSAMLPRequestBuilder(SAMLPRequestBuilder requestBuilder) {
        this.samlpRequestBuilder = requestBuilder;
    }
    
    public boolean isDisableDeflateEncoding() {
        return getSAMLProtocol().isDisableDeflateEncoding();
    }

    public void setDisableDeflateEncoding(boolean disableDeflateEncoding) {
        getSAMLProtocol().setDisableDeflateEncoding(disableDeflateEncoding);
    }
    
    public boolean isDoNotEnforceKnownIssuer() {
        return getSAMLProtocol().isDoNotEnforceKnownIssuer();
    }

    public void setDoNotEnforceKnownIssuer(boolean doNotEnforceKnownIssuer) {
        getSAMLProtocol().setDoNotEnforceKnownIssuer(doNotEnforceKnownIssuer);
    }
    
    public String getIssuerLogoutURL() {
        return getSAMLProtocol().getIssuerLogoutURL();
    }
}
