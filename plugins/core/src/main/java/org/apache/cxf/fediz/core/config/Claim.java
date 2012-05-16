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

import org.apache.cxf.fediz.core.config.jaxb.ClaimType;

public class Claim {

    private ClaimType claimType;

    public Claim(ClaimType claimType) {
        super();
        this.claimType = claimType;
    }

    protected ClaimType getClaimType() {
        return claimType;
    }

    protected void setClaimType(ClaimType claimType) {
        this.claimType = claimType;
    }

    public boolean isOptional() {
        return claimType.isOptional();
    }

    public int hashCode() {
        return claimType.hashCode();
    }

    public void setOptional(boolean value) {
        claimType.setOptional(value);
    }

    public String getType() {
        return claimType.getType();
    }

    public void setType(String value) {
        claimType.setType(value);
    }

    public boolean equals(Object obj) {
        return claimType.equals(obj);
    }

    public String toString() {
        return claimType.toString();
    }
    
    
    
}
