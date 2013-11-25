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

package org.apache.cxf.fediz.service.idp.rest;

import java.util.Map;

import javax.ws.rs.GET;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.xml.bind.annotation.XmlRootElement;

import org.apache.cxf.fediz.service.idp.model.TrustedIDPConfig;

@XmlRootElement
public class IDPTrustedIdps {

    private Map<String, TrustedIDPConfig> trustedIDPs;

    public IDPTrustedIdps() {
    }

    public IDPTrustedIdps(Map<String, TrustedIDPConfig> trustedIDPs) {
        this.trustedIDPs = trustedIDPs;
    }

    public Map<String, TrustedIDPConfig> getTrustedIDPs() {
        return trustedIDPs;
    }

    public void setTrustedIDPs(Map<String, TrustedIDPConfig> trustedIDPs) {
        this.trustedIDPs = trustedIDPs;
    }

    @GET
    @Path("wtrealm")
    public TrustedIDPConfig getTrustedIDPConfig(@PathParam("whr") String whr) {
        TrustedIDPConfig config = trustedIDPs.get(whr);
        if (config == null) {
            throw new NotFoundException();
        }
        return config;
    }

}