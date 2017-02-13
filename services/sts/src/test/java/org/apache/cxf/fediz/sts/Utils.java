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
package org.apache.cxf.fediz.sts;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.configuration.security.FiltersType;

public final class Utils {

    private Utils() {
    }

    public static void initTLSClientParameters(TLSClientParameters tlsClientParameters, String keystoreFile,
                                               String keystorePassword, String keyPassword,
                                               String truststoreFile, String trustPassword)
        throws URISyntaxException, GeneralSecurityException, IOException {

        tlsClientParameters.setDisableCNCheck(true);
        // System.setProperty("javax.net.debug", "all");
        if (keystoreFile != null && keystoreFile.length() > 0) {
            String keystore = new File(Thread.currentThread().getContextClassLoader()
                                       .getResource(keystoreFile).toURI()).getAbsolutePath();

            KeyManager[] kmgrs = getKeyManagers(getKeyStore("JKS", keystore, keystorePassword), keyPassword);
            tlsClientParameters.setKeyManagers(kmgrs);
        }

        String truststore = new File(Thread.currentThread().getContextClassLoader()
                                     .getResource(truststoreFile).toURI()).getAbsolutePath();

        TrustManager[] tmgrs = getTrustManagers(getKeyStore("JKS", truststore, trustPassword));

        tlsClientParameters.setTrustManagers(tmgrs);
        FiltersType filters = new FiltersType();
        filters.getInclude().add(".*_EXPORT_.*");
        filters.getInclude().add(".*_EXPORT1024_.*");
        filters.getInclude().add(".*_WITH_DES_.*");
        filters.getInclude().add(".*_WITH_AES_.*");
        filters.getInclude().add(".*_WITH_NULL_.*");
        filters.getInclude().add(".*_DH_anon_.*");
        tlsClientParameters.setCipherSuitesFilter(filters);

    }

    public static KeyManager[] getKeyManagers(KeyStore keyStore, String keyPassword)
        throws GeneralSecurityException, IOException {
        // For tests, we just use the default algorithm
        String alg = KeyManagerFactory.getDefaultAlgorithm();
        char[] keyPass = keyPassword != null ? keyPassword.toCharArray() : null;
        // For tests, we just use the default provider.
        KeyManagerFactory fac = KeyManagerFactory.getInstance(alg);
        fac.init(keyStore, keyPass);
        return fac.getKeyManagers();
    }

    public static TrustManager[] getTrustManagers(KeyStore keyStore) throws GeneralSecurityException, IOException {
        // For tests, we just use the default algorithm
        String alg = TrustManagerFactory.getDefaultAlgorithm();
        // For tests, we just use the default provider.
        TrustManagerFactory fac = TrustManagerFactory.getInstance(alg);
        fac.init(keyStore);
        return fac.getTrustManagers();
    }

    public static KeyStore getKeyStore(String ksType, String file, String ksPassword)
        throws GeneralSecurityException, IOException {
        String type = ksType != null ? ksType : KeyStore.getDefaultType();
        char[] password = ksPassword != null ? ksPassword.toCharArray() : null;
        // We just use the default Keystore provider
        KeyStore keyStore = KeyStore.getInstance(type);
        try (FileInputStream inputStream = new FileInputStream(file)) {
            keyStore.load(inputStream, password);
        }
        return keyStore;
    }

}
