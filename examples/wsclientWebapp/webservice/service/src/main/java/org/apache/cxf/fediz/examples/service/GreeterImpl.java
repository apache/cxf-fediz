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

package org.apache.cxf.fediz.examples.service;

import java.security.Principal;

import javax.annotation.Resource;
import javax.xml.ws.WebServiceContext;

import org.apache.hello_world_soap_http.Greeter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GreeterImpl implements Greeter {

    private static final Logger LOG = LoggerFactory.getLogger(GreeterImpl.class.getPackage().getName());

    @Resource
    WebServiceContext context;

    public String greetMe() {
        LOG.info("Executing operation greetMe");
        System.out.println("Executing operation greetMe");
        if (context == null) {
            return "Unknown user";
        } else {
            Principal p = context.getUserPrincipal();
            if (p == null) {
                return "Principal null";
            }
            return p.getName();
        }
    }

}
