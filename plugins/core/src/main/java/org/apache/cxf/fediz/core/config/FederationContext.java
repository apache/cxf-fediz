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
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.apache.cxf.fediz.core.EHCacheTokenReplayCache;
import org.apache.cxf.fediz.core.TokenReplayCache;
import org.apache.cxf.fediz.core.config.jaxb.CertificateStores;
import org.apache.cxf.fediz.core.config.jaxb.ContextConfig;
import org.apache.cxf.fediz.core.config.jaxb.FederationProtocolType;
import org.apache.cxf.fediz.core.config.jaxb.KeyStoreType;
import org.apache.cxf.fediz.core.config.jaxb.ProtocolType;
import org.apache.cxf.fediz.core.config.jaxb.TrustManagersType;
import org.apache.cxf.fediz.core.config.jaxb.TrustedIssuerType;
import org.apache.cxf.fediz.core.config.jaxb.TrustedIssuers;
import org.apache.cxf.fediz.core.exception.IllegalConfigurationException;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.util.Loader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FederationContext implements Closeable {

    private static final Logger LOG = LoggerFactory.getLogger(FederationContext.class);
    
    private ContextConfig config;

    private boolean detectExpiredTokens = true;
    private boolean detectReplayedTokens = true;
    private String relativePath;
    private TokenReplayCache<String> replayCache;
    private FederationProtocol protocol;
    private List<TrustManager> certificateStores;
    

    public FederationContext(ContextConfig config) {
        this.config = config;
        
    }
    
    public void init() {
        //get validators initialized
        getProtocol();
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
        if (certificateStores != null) {
            return certificateStores;
        }
        certificateStores = new ArrayList<TrustManager>();
        CertificateStores certStores = config.getCertificateStores();
        List<TrustManagersType> trustManagers = certStores.getTrustManager();
        for (TrustManagersType manager:trustManagers) {
            TrustManager tm = new TrustManager(manager);
            Properties sigProperties = createCryptoProperties(manager);
            Crypto crypto;
            try {
                crypto = CryptoFactory.getInstance(sigProperties);
                tm.setCrypto(crypto);
                certificateStores.add(tm);
            } catch (WSSecurityException e) {
                LOG.error("Failed to load keystore '" + tm.getName() + "'");
                throw new IllegalConfigurationException("Failed to load keystore '" + tm.getName() + "'");
            }
        }
        return certificateStores; 
    }

    public BigInteger getMaximumClockSkew() {
        return config.getMaximumClockSkew();
    }
    
    public void setMaximumClockSkew(BigInteger maximumClockSkew) {
        config.setMaximumClockSkew(maximumClockSkew);
    }

    //    public TrustManager getServiceCertificate() {
    //        return new TrustManager(config.getServiceCertificate());
    //    }

    public Protocol getProtocol() {
        if (protocol != null) {
            return protocol;
        }
        ProtocolType type = config.getProtocol();
        if (type instanceof FederationProtocolType) {
            protocol = new FederationProtocol(type);
        }
        return protocol;
    }
    
    @SuppressWarnings("unchecked")
    public TokenReplayCache<String> getTokenReplayCache() {
        if (replayCache != null) {
            return replayCache;
        }
        String replayCacheString = config.getTokenReplayCache();
        String cacheKey = "fediz-replay-cache-" + config.getName();
        if (replayCacheString == null || "".equals(replayCacheString)) {
            replayCache = new EHCacheTokenReplayCache(cacheKey);
        } else {
            try {
                Class<?> replayCacheClass = Loader.loadClass(replayCacheString);
                replayCache = (TokenReplayCache<String>) replayCacheClass.newInstance();
            } catch (ClassNotFoundException e) {
                replayCache = new EHCacheTokenReplayCache(cacheKey);
            } catch (InstantiationException e) {
                replayCache = new EHCacheTokenReplayCache(cacheKey);
            } catch (IllegalAccessException e) {
                replayCache = new EHCacheTokenReplayCache(cacheKey);
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
    
    private Properties createCryptoProperties(TrustManagersType tm) {
        String trustStoreFile = null;
        String trustStorePw = null;
        KeyStoreType ks = tm.getKeyStore();
        if (ks.getFile() != null && !ks.getFile().isEmpty()) {
            trustStoreFile = ks.getFile();
            trustStorePw = ks.getPassword();
        } else {
            throw new IllegalStateException("No certificate store configured");
        }
        File f = new File(trustStoreFile);
        if (!f.exists() && getRelativePath() != null && !getRelativePath().isEmpty()) {
            trustStoreFile = getRelativePath().concat(File.separator + trustStoreFile);
        }
        
        if (trustStoreFile == null || trustStoreFile.isEmpty()) {
            throw new NullPointerException("truststoreFile not configured");
        }
        if (trustStorePw == null || trustStorePw.isEmpty()) {
            throw new NullPointerException("trustStorePw not configured");
        }
        Properties p = new Properties();
        p.put("org.apache.ws.security.crypto.provider",
                "org.apache.ws.security.components.crypto.Merlin");
        p.put("org.apache.ws.security.crypto.merlin.keystore.type", "jks");
        p.put("org.apache.ws.security.crypto.merlin.keystore.password",
              trustStorePw);
        p.put("org.apache.ws.security.crypto.merlin.keystore.file",
              trustStoreFile);
        return p;
    }

}
