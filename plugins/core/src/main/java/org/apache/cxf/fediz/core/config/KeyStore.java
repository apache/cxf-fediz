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
    private KeyStoreType kesyStoreType = null;

    public KeyStore(KeyStoreType kesyStoreType) {
        super();
        this.kesyStoreType = kesyStoreType;
    }

    protected KeyStoreType getKesyStoreType() {
        return kesyStoreType;
    }

    protected void setKesyStoreType(KeyStoreType kesyStoreType) {
        this.kesyStoreType = kesyStoreType;
    }

    public String getType() {
        return kesyStoreType.getType();
    }

    public void setType(String value) {
        kesyStoreType.setType(value);
    }

    public String getPassword() {
        return kesyStoreType.getPassword();
    }

    public void setPassword(String value) {
        kesyStoreType.setPassword(value);
    }

    public String getProvider() {
        return kesyStoreType.getProvider();
    }

    public void setProvider(String value) {
        kesyStoreType.setProvider(value);
    }

    public String getUrl() {
        return kesyStoreType.getUrl();
    }

    public void setUrl(String value) {
        kesyStoreType.setUrl(value);
    }

    public String getFile() {
        return kesyStoreType.getFile();
    }

    public void setFile(String value) {
        kesyStoreType.setFile(value);
    }

    public String getResource() {
        return kesyStoreType.getResource();
    }

    public void setResource(String value) {
        kesyStoreType.setResource(value);
    }

    public int hashCode() {
        return kesyStoreType.hashCode();
    }

    public boolean equals(Object obj) {
        return kesyStoreType.equals(obj);
    }

    public String toString() {
        return kesyStoreType.toString();
    }

}
