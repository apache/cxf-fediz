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

import org.apache.cxf.fediz.core.config.jaxb.CertStoreType;

public class CertStore {
    private CertStoreType certStoreType = null;

    public CertStore(CertStoreType certStoreType) {
        super();
        this.certStoreType = certStoreType;
    }

    protected CertStoreType getCertStoreType() {
        return certStoreType;
    }

    protected void setCertStoreType(CertStoreType certStoreType) {
        this.certStoreType = certStoreType;
    }

    public int hashCode() {
        return certStoreType.hashCode();
    }

    public String getFile() {
        return certStoreType.getFile();
    }

    public void setFile(String value) {
        certStoreType.setFile(value);
    }

    public String getResource() {
        return certStoreType.getResource();
    }

    public void setResource(String value) {
        certStoreType.setResource(value);
    }

    public String getUrl() {
        return certStoreType.getUrl();
    }

    public void setUrl(String value) {
        certStoreType.setUrl(value);
    }

    public boolean equals(Object obj) {
        return certStoreType.equals(obj);
    }

    public String toString() {
        return certStoreType.toString();
    }

}
