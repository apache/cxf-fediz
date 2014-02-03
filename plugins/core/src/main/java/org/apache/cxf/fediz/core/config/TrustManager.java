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

import org.apache.cxf.fediz.core.config.jaxb.TrustManagersType;
import org.apache.wss4j.common.crypto.Crypto;

public class TrustManager {
    
    private TrustManagersType trustManagerType;
    private Crypto crypto;
    private String name;

    public TrustManager(TrustManagersType trustManagerType) {
        super();
        this.trustManagerType = trustManagerType;
    }

    public String getName() {
        if (name != null) {
            return name;
        }
        if (trustManagerType.getKeyStore().getFile() != null) {
            name = trustManagerType.getKeyStore().getFile();
        } else if (trustManagerType.getKeyStore().getUrl() != null) {
            name = trustManagerType.getKeyStore().getUrl();
        } else if (trustManagerType.getKeyStore().getResource() != null) {
            name = trustManagerType.getKeyStore().getResource();
        }
        return name;
    }

    public Crypto getCrypto() {
        return crypto;
    }

    public void setCrypto(Crypto crypto) {
        this.crypto = crypto;
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
