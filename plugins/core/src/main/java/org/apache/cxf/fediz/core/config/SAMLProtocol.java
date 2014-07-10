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

public class SAMLProtocol extends Protocol {

    // private static final Logger LOG = LoggerFactory.getLogger(SAMLProtocol.class);
    
    public SAMLProtocol(ProtocolType protocolType) {
        super(protocolType);
        
        /*FederationProtocolType fp = (FederationProtocolType)protocolType;
        if (fp.getTokenValidators() != null && fp.getTokenValidators().getValidator() != null) {
            for (String validatorClassname : fp.getTokenValidators().getValidator()) {
                Object obj = null;
                try {
                    if (super.getClassloader() == null) {
                        obj = ClassLoaderUtils.loadClass(validatorClassname, this.getClass()).newInstance();
                    } else {
                        obj = super.getClassloader().loadClass(validatorClassname).newInstance();
                    }
                } catch (Exception ex) {
                    LOG.error("Failed to instantiate TokenValidator implementation class: '"
                              + validatorClassname + "'\n" + ex.getClass().getCanonicalName() + ": " + ex.getMessage());
                }
                if (obj instanceof TokenValidator) {
                    validators.add((TokenValidator)obj);
                } else if (obj != null) {
                    LOG.error("Invalid TokenValidator implementation class: '" + validatorClassname + "'");
                }
            }
        }*/
        
        // add SAMLTokenValidator as the last one
        // Fediz chooses the first validator in the list if its
        // canHandleToken or canHandleTokenType method return true
        //SAMLTokenValidator validator = new SAMLTokenValidator();
        //validators.add(validators.size(), validator);
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
    
    public String getWebAppDomain() {
        return getSAMLProtocol().getWebAppDomain();
    }
    
    public void setWebAppDomain(String webAppDomain) {
        getSAMLProtocol().setWebAppDomain(webAppDomain);
    }

    public long getStateTimeToLive() {
        long ttl = getSAMLProtocol().getStateTimeToLive();
        if (ttl > 0) {
            return ttl;
        }
        return 2L * 60L * 1000L;
    }
    
    public void setStateTimeToLive(long stateTimeToLive) {
        getSAMLProtocol().setStateTimeToLive(stateTimeToLive);
    }

    
}
