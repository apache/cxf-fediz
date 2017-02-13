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

import java.util.List;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.apache.cxf.fediz.service.idp.protocols.ProtocolController;
import org.apache.cxf.fediz.service.idp.spi.ApplicationProtocolHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

/**
 * Validate that the protocol is a valid Application protocol
 */
@Component
public class ApplicationIdpProtocolSupportValidator
    implements ConstraintValidator<ApplicationProtocolSupported, String> {

    @Autowired
    @Qualifier("applicationProtocolControllerImpl")
    private ProtocolController<ApplicationProtocolHandler> applicationProtocolHandlers;

    @Override
    public boolean isValid(String object, ConstraintValidatorContext constraintContext) {

        List<String> protocols = applicationProtocolHandlers.getProtocols();
        return protocols.contains(object);
    }

    @Override
    public void initialize(ApplicationProtocolSupported constraintAnnotation) {
    }

}
