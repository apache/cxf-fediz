/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.cxf.fediz.core.config;

import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.cxf.fediz.core.exception.IllegalConfigurationException;

public class FederationContext {

    private ContextConfig config = null;

    private boolean detectExpiredTokens = true;
    private boolean detectReplayedTokens = true;

    public FederationContext(ContextConfig config) {
        this.config = config;
    }

    public List<String> getAudienceUris() {
        return config.getAudienceUris().getAudienceItem();
    }

    public ValidationType getCertificateValidation() {
        return config.getCertificateValidation();
    }

    public TrustedIssuers getTrustedIssuers() {
        return config.getTrustedIssuers();
    }

    public BigInteger getMaximumClockSkew() {
        return config.getMaximumClockSkew();
    }

    public TrustManagersType getServiceCertificate() {
        return config.getServiceCertificate();
    }

    public ProtocolType getProtocol() {
        return config.getProtocol();
    }

    public String getName() {
        return config.getName();
    }

    /**
     * helpers to support existing testcases
     */

    public boolean isDetectExpiredTokens() {
        return detectExpiredTokens;
    }

    public void setDetectExpiredTokens(boolean detectExpiredTokens) {
        this.detectExpiredTokens = detectExpiredTokens;
    }

    public boolean isDetectReplayedTokens() {
        return detectReplayedTokens;
    }

    public void setDetectReplayedTokens(boolean detectReplayedTokens) {
        this.detectReplayedTokens = detectReplayedTokens;
    }

    public List<String> getTrustedIssuersNames() {
        TrustedIssuers issuers = config.getTrustedIssuers();
        List<String> issuerNames = new ArrayList<String>();
        if (issuers != null) {
            for (TrustManagersType t : issuers.getTrustedIssuerItem()) {
                issuerNames.add(t.getProvider());
            }
            return issuerNames;
        } else {
            return Collections.<String> emptyList();
        }
    }

    public URI getRoleURI() {
        ProtocolType pt = config.getProtocol();
        if (pt != null && pt instanceof FederationProtocolType) {
            try {
                return new URI(((FederationProtocolType) pt).getRoleURI());
            } catch (URISyntaxException e) {
                throw new IllegalConfigurationException("Invalid Role URI", e);
            }
        }
        if (pt != null && !(pt instanceof FederationProtocolType)) {
            throw new IllegalConfigurationException(
                    "Unknown Protocoltype, only FederationProtocolType is currently suported");
        }
        if (pt == null) {
            throw new IllegalConfigurationException("Missing ProtocolType");
        }
        return null;

    }

    public String getRoleDelimiter() {
        ProtocolType pt = config.getProtocol();
        if (pt != null && pt instanceof FederationProtocolType) {
            return ((FederationProtocolType) pt).getRoleDelimiter();
        }
        throw new IllegalConfigurationException(
                "No FederationProtocolType found");
    }

    public String getTrustStoreFile() {
        KeyStoreType storeType = getTrustStore();
        return storeType.getFile();
    }

    public String getTrustStorePassword() {
        KeyStoreType storeType = getTrustStore();
        return storeType.getPassword();
    }

    private KeyStoreType getTrustStore() {
        List<TrustManagersType> managers = config.getTrustedIssuers()
                .getTrustedIssuerItem();
        if (managers == null) {
            throw new IllegalConfigurationException(
                    "No Trusted Issuers Keystore found");
        }
        if (managers.size() > 1) {
            throw new IllegalConfigurationException(
                    "Only one Trusted Issuer Keystore supported");
        }
        TrustManagersType trustManager = managers.get(0);
        KeyStoreType storeType = trustManager.getKeyStore();
        return storeType;
    }

}
