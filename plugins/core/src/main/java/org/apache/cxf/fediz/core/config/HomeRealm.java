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

import org.apache.cxf.fediz.core.config.jaxb.ArgumentType;

public class HomeRealm {
    private org.apache.cxf.fediz.core.config.jaxb.HomeRealm homeRealm;

    public HomeRealm(org.apache.cxf.fediz.core.config.jaxb.HomeRealm homeRealm) {
        super();
        this.homeRealm = homeRealm;
    }

    protected org.apache.cxf.fediz.core.config.jaxb.HomeRealm getHomeRealm() {
        return homeRealm;
    }

    protected void setHomeRealm(org.apache.cxf.fediz.core.config.jaxb.HomeRealm homeRealm) {
        this.homeRealm = homeRealm;
    }

    public ArgumentType getType() {
        return homeRealm.getType();
    }

    public int hashCode() {
        return homeRealm.hashCode();
    }

    public void setType(ArgumentType value) {
        homeRealm.setType(value);
    }

    public String getValue() {
        return homeRealm.getValue();
    }

    public void setValue(String value) {
        homeRealm.setValue(value);
    }

    public boolean equals(Object obj) {
        return homeRealm.equals(obj);
    }

    public String toString() {
        return homeRealm.toString();
    }

    
    
}