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
package org.apache.cxf.fediz.service.idp.service.jpa;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;

@Entity(name = "Application_Claim")
//@IdClass(ApplicationClaimId.class)
public class ApplicationClaimEntity {
    
    @Id
    private int id;
    
    @ManyToOne
    @JoinColumn(name = "applicationid")
    private ApplicationEntity application;
 
    @ManyToOne
    @JoinColumn(name = "claimid")
    private ClaimEntity claim;
 
    private boolean optional;
    
    public ApplicationClaimEntity() {
    }
    
    public ApplicationClaimEntity(ApplicationEntity application, ClaimEntity claim) {
        super();
        this.application = application;
        this.claim = claim;
    }
    
    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public boolean isOptional() {
        return optional;
    }

    public void setOptional(boolean optional) {
        this.optional = optional;
    }

    public ApplicationEntity getApplication() {
        return application;
    }

    public void setApplication(ApplicationEntity application) {
        this.application = application;
    }

    public ClaimEntity getClaim() {
        return claim;
    }

    public void setClaim(ClaimEntity claim) {
        this.claim = claim;
    }
}
