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

import org.apache.cxf.fediz.core.config.jaxb.TrustManagersType;

public class TrustManager {
    private TrustManagersType trustManagerType;

    public TrustManager(TrustManagersType trustManagerType) {
        super();
        this.trustManagerType = trustManagerType;
    }

    public KeyStore getKeyStore() {
        return new KeyStore(trustManagerType.getKeyStore());
    }

    public void setKeyStore(KeyStore keyStore) {
        trustManagerType.setKeyStore(keyStore.getkeyStoreType());
    }

    public String getProvider() {
        return trustManagerType.getProvider();
    }

    public void setProvider(String value) {
        trustManagerType.setProvider(value);
    }

    public int hashCode() {
        return trustManagerType.hashCode();
    }
    
    public boolean equals(Object obj) {
        return trustManagerType.equals(obj);
    }

    public String toString() {
        return trustManagerType.toString();
    }
    

}
