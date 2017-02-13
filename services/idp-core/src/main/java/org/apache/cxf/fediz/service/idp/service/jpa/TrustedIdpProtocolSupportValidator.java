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
import org.apache.cxf.fediz.service.idp.spi.TrustedIdpProtocolHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

/**
 * Validate that the protocol is a valid IdP protocol
 */
@Component
public class TrustedIdpProtocolSupportValidator implements ConstraintValidator<TrustedIdpProtocolSupported, String> {

    @Autowired
    // Qualifier workaround. See http://www.jayway.com/2013/11/03/spring-and-autowiring-of-generic-types/
    @Qualifier("trustedIdpProtocolControllerImpl")
    private ProtocolController<TrustedIdpProtocolHandler> trustedIdpProtocolHandlers;

    @Override
    public boolean isValid(String object, ConstraintValidatorContext constraintContext) {

        List<String> protocols = trustedIdpProtocolHandlers.getProtocols();
        return protocols.contains(object);
    }

    @Override
    public void initialize(TrustedIdpProtocolSupported constraintAnnotation) {
    }

}