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
package org.apache.cxf.fediz.service.idp.model;

import java.util.ArrayList;
import java.util.Map;

import org.apache.cxf.fediz.service.idp.domain.Application;
import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.apache.cxf.fediz.service.idp.domain.TrustedIdp;

public class IDPConfig extends Idp {

    private static final long serialVersionUID = -5570301342547139039L;

    public void setServices(Map<String, Application> applications) {
        this.applications = new ArrayList<>(applications.values());
    }
    
    public void setTrustedIdps(Map<String, TrustedIDPConfig> trustedIdps) {
        this.trustedIdpList = new ArrayList<TrustedIdp>(trustedIdps.values());
    }
    
    @Deprecated
    public void setTrustedIDPs(Map<String, TrustedIDPConfig> trustedIdps) {
        setTrustedIdps(trustedIdps);
    }
}
