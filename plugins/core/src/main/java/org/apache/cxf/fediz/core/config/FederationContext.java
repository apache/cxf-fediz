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

import java.io.Closeable;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.apache.cxf.fediz.core.EHCacheTokenReplayCache;
import org.apache.cxf.fediz.core.TokenReplayCache;
import org.apache.cxf.fediz.core.config.jaxb.CertificateStores;
import org.apache.cxf.fediz.core.config.jaxb.ContextConfig;
import org.apache.cxf.fediz.core.config.jaxb.FederationProtocolType;
import org.apache.cxf.fediz.core.config.jaxb.ProtocolType;
import org.apache.cxf.fediz.core.config.jaxb.TrustManagersType;
import org.apache.cxf.fediz.core.config.jaxb.TrustedIssuerType;
import org.apache.cxf.fediz.core.config.jaxb.TrustedIssuers;

import org.apache.ws.security.util.Loader;

public class FederationContext implements Closeable {

    private ContextConfig config;

    private boolean detectExpiredTokens = true;
    private boolean detectReplayedTokens = true;
    private String relativePath;
    private TokenReplayCache<String> replayCache;

    public FederationContext(ContextConfig config) {
        this.config = config;
    }

    public List<String> getAudienceUris() {
        return config.getAudienceUris().getAudienceItem();
    }

    public List<TrustedIssuer> getTrustedIssuers() {
        TrustedIssuers issuers = config.getTrustedIssuers();
        List<TrustedIssuerType> trustManagers =  issuers.getIssuer();
        List<TrustedIssuer> trustedIssuers = new ArrayList<TrustedIssuer>();
        for (TrustedIssuerType manager:trustManagers) {
            trustedIssuers.add(new TrustedIssuer(manager));
        }
        return trustedIssuers; 
    }


    public List<TrustManager> getCertificateStores() {
        CertificateStores certStores = config.getCertificateStores();
        List<TrustManagersType> trustManagers =  certStores.getTrustManager();
        List<TrustManager> trustedIssuers = new ArrayList<TrustManager>();
        for (TrustManagersType manager:trustManagers) {
            trustedIssuers.add(new TrustManager(manager));
        }
        return trustedIssuers; 
    }

    public BigInteger getMaximumClockSkew() {
        return config.getMaximumClockSkew();
    }
    
    public void setMaximumClockSkew(BigInteger maximumClockSqew) {
        config.setMaximumClockSkew(maximumClockSqew);
    }

    //    public TrustManager getServiceCertificate() {
    //        return new TrustManager(config.getServiceCertificate());
    //    }

    public Protocol getProtocol() {
        ProtocolType type = config.getProtocol();
        if (type instanceof FederationProtocolType) {
            return new FederationProtocol(type);
        }
        return null;
    }
    
    @SuppressWarnings("unchecked")
    public TokenReplayCache<String> getTokenReplayCache() {
        if (replayCache != null) {
            return replayCache;
        }
        String replayCacheString = config.getTokenReplayCache();
        if (replayCacheString == null || "".equals(replayCacheString)) {
            replayCache = new EHCacheTokenReplayCache();
        } else {
            try {
                Class<?> replayCacheClass = Loader.loadClass(replayCacheString);
                replayCache = (TokenReplayCache<String>) replayCacheClass.newInstance();
            } catch (ClassNotFoundException e) {
                replayCache = new EHCacheTokenReplayCache();
            } catch (InstantiationException e) {
                replayCache = new EHCacheTokenReplayCache();
            } catch (IllegalAccessException e) {
                replayCache = new EHCacheTokenReplayCache();
            }
        }
        return replayCache;
    }

    public String getName() {
        return config.getName();
    }


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

    public void setRelativePath(String relativePath) {
        this.relativePath = relativePath;
    }

    public String getRelativePath() {
        return relativePath;
    }

    @Override
    public void close() throws IOException {
        if (replayCache != null) {
            replayCache.close();
        }
    }

}
