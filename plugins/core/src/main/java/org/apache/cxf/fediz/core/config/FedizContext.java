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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import org.apache.cxf.fediz.core.config.jaxb.CertificateStores;
import org.apache.cxf.fediz.core.config.jaxb.ContextConfig;
import org.apache.cxf.fediz.core.config.jaxb.FederationProtocolType;
import org.apache.cxf.fediz.core.config.jaxb.KeyManagersType;
import org.apache.cxf.fediz.core.config.jaxb.KeyStoreType;
import org.apache.cxf.fediz.core.config.jaxb.ProtocolType;
import org.apache.cxf.fediz.core.config.jaxb.SamlProtocolType;
import org.apache.cxf.fediz.core.config.jaxb.TrustManagersType;
import org.apache.cxf.fediz.core.config.jaxb.TrustedIssuerType;
import org.apache.cxf.fediz.core.config.jaxb.TrustedIssuers;
import org.apache.cxf.fediz.core.exception.IllegalConfigurationException;
import org.apache.cxf.fediz.core.util.CertsUtils;
import org.apache.wss4j.common.cache.ReplayCache;
import org.apache.wss4j.common.cache.ReplayCacheFactory;
import org.apache.wss4j.common.crypto.CertificateStore;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.Loader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FedizContext implements Closeable {
    
    public static final String CACHE_KEY_PREFIX = "fediz.replay.cache";

    private static final Logger LOG = LoggerFactory.getLogger(FedizContext.class);
    
    private ContextConfig config;

    private boolean detectReplayedTokens = true;
    private String relativePath;
    private ReplayCache replayCache;
    private Protocol protocol;
    private List<TrustManager> certificateStores = new ArrayList<>();
    private KeyManager keyManager;
    private KeyManager decryptionKeyManager;
    private ClassLoader classloader;
    

    public FedizContext(ContextConfig config) {
        if (config == null) {
            throw new IllegalArgumentException("ContextConfig cannot be null!");
        }
        this.config = config;
        
    }
    
    public void init() {
        //get validators initialized
        getProtocol();
    }

    public List<String> getAudienceUris() {
        if (config.getAudienceUris() == null) {
            return Collections.emptyList();
        }
        return config.getAudienceUris().getAudienceItem();
    }

    public List<TrustedIssuer> getTrustedIssuers() {
        TrustedIssuers issuers = config.getTrustedIssuers();
        List<TrustedIssuerType> trustManagers =  issuers.getIssuer();
        List<TrustedIssuer> trustedIssuers = new ArrayList<>();
        for (TrustedIssuerType manager:trustManagers) {
            trustedIssuers.add(new TrustedIssuer(manager));
        }
        return trustedIssuers; 
    }
    
    public List<TrustManager> getCertificateStores() {
        if (!certificateStores.isEmpty()) {
            return Collections.unmodifiableList(certificateStores);
        }
        
        CertificateStores certStores = config.getCertificateStores();
        List<TrustManagersType> trustManagers = certStores.getTrustManager();
        for (TrustManagersType manager : trustManagers) {
            TrustManager tm = new TrustManager(manager);
            
            Crypto crypto = null;
            try {
                if (manager.getKeyStore().getType().equalsIgnoreCase("PEM")) {
                    X509Certificate[] certificates = new X509Certificate[1];
                    certificates[0] = CertsUtils.getX509CertificateFromFile(tm.getName(), classloader);
                    crypto = new CertificateStore(certificates);
                } else {
                    Properties sigProperties = createCryptoProperties(manager);
                    crypto = CryptoFactory.getInstance(sigProperties);
                }
                tm.setCrypto(crypto);
                certificateStores.add(tm);
            } catch (WSSecurityException e) {
                LOG.error("Failed to load keystore '" + tm.getName() + "'", e);
                throw new IllegalConfigurationException("Failed to load keystore '" + tm.getName() + "'");
            } catch (CertificateException ex) {
                LOG.error("Failed to read keystore", ex);
                throw new RuntimeException("Failed to read keystore");
            }
        }
        return Collections.unmodifiableList(certificateStores); 
    }

    public BigInteger getMaximumClockSkew() {
        if (config.getMaximumClockSkew() == null) {
            return BigInteger.valueOf(5L);
        } else {
            return config.getMaximumClockSkew();
        }
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
        } else if (type instanceof SamlProtocolType) {
            protocol = new SAMLProtocol(type);
        }
        
        if (protocol != null) {
            protocol.setClassloader(getClassloader());
        }
        return protocol;
    }

    public String getLogoutURL() {
        return config.getLogoutURL();
    }

    public String getLogoutRedirectTo() {
        return config.getLogoutRedirectTo();
    }
    
    
    public KeyManager getSigningKey() {
        
        if (keyManager != null) {
            return keyManager;
        }
        if (config.getSigningKey() == null) {
            LOG.error("No signing key has been configured");
            throw new IllegalConfigurationException("No signing key has been configured");
        }
        keyManager = new KeyManager(config.getSigningKey());
        Properties sigProperties = createCryptoProperties(config.getSigningKey());
        try {
            Crypto crypto = CryptoFactory.getInstance(sigProperties);
            keyManager.setCrypto(crypto);
        } catch (WSSecurityException e) {
            String name = keyManager.getName();
            keyManager = null;
            LOG.error("Failed to load keystore '" + name + "'", e);
            throw new IllegalConfigurationException("Failed to load keystore '" + name + "'");
        }
        
        return keyManager; 
        
    }
    
    public KeyManager getDecryptionKey() {
        if (decryptionKeyManager != null) {
            return decryptionKeyManager;
        }
        if (config.getTokenDecryptionKey() == null) {
            return null;
        }
        decryptionKeyManager = new KeyManager(config.getTokenDecryptionKey());
        Properties decProperties = createCryptoProperties(config.getTokenDecryptionKey());
        try {
            Crypto crypto = CryptoFactory.getInstance(decProperties);
            decryptionKeyManager.setCrypto(crypto);
        } catch (WSSecurityException e) {
            String name = decryptionKeyManager.getName();
            decryptionKeyManager = null;
            LOG.error("Failed to load keystore '" + name + "'", e);
            throw new IllegalConfigurationException("Failed to load keystore '" + name + "'");
        }
        
        return decryptionKeyManager; 
        
    }

    public ReplayCache getTokenReplayCache() {
        if (replayCache != null) {
            return replayCache;
        }
        String replayCacheString = config.getTokenReplayCache();
        String cacheKey = CACHE_KEY_PREFIX + "-" + config.getName();
        ReplayCacheFactory replayCacheFactory = ReplayCacheFactory.newInstance();
        if (replayCacheString == null || "".equals(replayCacheString)) {
            replayCache = replayCacheFactory.newReplayCache(cacheKey, "/fediz-ehcache.xml");
        } else {
            try {
                Class<?> replayCacheClass = Loader.loadClass(replayCacheString);
                replayCache = (ReplayCache) replayCacheClass.newInstance();
            } catch (ClassNotFoundException e) {
                replayCache = replayCacheFactory.newReplayCache(cacheKey, "/fediz-ehcache.xml");
            } catch (InstantiationException e) {
                replayCache = replayCacheFactory.newReplayCache(cacheKey, "/fediz-ehcache.xml");
            } catch (IllegalAccessException e) {
                replayCache = replayCacheFactory.newReplayCache(cacheKey, "/fediz-ehcache.xml");
            }
        }
        return replayCache;
    }

    public String getName() {
        return config.getName();
    }


    public boolean isDetectExpiredTokens() {
        return config.isTokenExpirationValidation();
    }
    
    public void setDetectExpiredTokens(boolean detectExpiredTokens) {
        config.setTokenExpirationValidation(detectExpiredTokens);
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
            throw new IllegalConfigurationException("truststoreFile not configured");
        }
        if (trustStorePw == null || trustStorePw.isEmpty()) {
            throw new IllegalConfigurationException("trustStorePw not configured");
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
    
    private Properties createCryptoProperties(KeyManagersType km) {
        String keyStoreFile = null;
        String keyStorePw = null;
        String keyType = "jks";
        KeyStoreType ks = km.getKeyStore();
        if (ks.getFile() != null && !ks.getFile().isEmpty()) {
            keyStoreFile = ks.getFile();
            keyStorePw = ks.getPassword();
        } else {
            throw new IllegalStateException("No certificate store configured");
        }
        File f = new File(keyStoreFile);
        if (!f.exists() && getRelativePath() != null && !getRelativePath().isEmpty()) {
            keyStoreFile = getRelativePath().concat(File.separator + keyStoreFile);
        }
        
        if (keyStoreFile == null || keyStoreFile.isEmpty()) {
            throw new IllegalConfigurationException("truststoreFile not configured");
        }
        if (keyStorePw == null || keyStorePw.isEmpty()) {
            throw new IllegalConfigurationException("trustStorePw not configured");
        }
        if (ks.getType() != null) {
            keyType = ks.getType();
        }
        
        Properties p = new Properties();
        p.put("org.apache.ws.security.crypto.provider",
                "org.apache.ws.security.components.crypto.Merlin");
        p.put("org.apache.ws.security.crypto.merlin.keystore.type", keyType);
        p.put("org.apache.ws.security.crypto.merlin.keystore.password",
              keyStorePw);
        p.put("org.apache.ws.security.crypto.merlin.keystore.file",
              keyStoreFile);
        return p;
    }
    
    public ClassLoader getClassloader() {
        return classloader;
    }

    public void setClassloader(ClassLoader classloader) {
        this.classloader = classloader;
    }
    
    

}
