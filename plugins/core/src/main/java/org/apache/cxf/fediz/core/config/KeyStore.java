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

import org.apache.cxf.fediz.core.config.jaxb.KeyStoreType;

public class KeyStore {
    private KeyStoreType keyStoreType;

    public KeyStore(KeyStoreType keyStoreType) {
        super();
        this.keyStoreType = keyStoreType;
    }

    protected KeyStoreType getkeyStoreType() {
        return keyStoreType;
    }

    protected void setkeyStoreType(KeyStoreType keyStoreType) {
        this.keyStoreType = keyStoreType;
    }

    public String getType() {
        return keyStoreType.getType();
    }

    public void setType(String value) {
        keyStoreType.setType(value);
    }

    public String getPassword() {
        return keyStoreType.getPassword();
    }

    public void setPassword(String value) {
        keyStoreType.setPassword(value);
    }

    public String getProvider() {
        return keyStoreType.getProvider();
    }

    public void setProvider(String value) {
        keyStoreType.setProvider(value);
    }

    public String getUrl() {
        return keyStoreType.getUrl();
    }

    public void setUrl(String value) {
        keyStoreType.setUrl(value);
    }

    public String getFile() {
        return keyStoreType.getFile();
    }

    public void setFile(String value) {
        keyStoreType.setFile(value);
    }

    public String getResource() {
        return keyStoreType.getResource();
    }

    public void setResource(String value) {
        keyStoreType.setResource(value);
    }

    public int hashCode() {
        return keyStoreType.hashCode();
    }

    public boolean equals(Object obj) {
        return keyStoreType.equals(obj);
    }

    public String toString() {
        return keyStoreType.toString();
    }

}
