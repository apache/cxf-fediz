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

import org.apache.bval.jsr303.ConstraintValidatorContextImpl;
import org.apache.cxf.fediz.service.idp.protocols.ProtocolController;
import org.apache.cxf.fediz.service.idp.spi.ApplicationProtocolHandler;
import org.apache.cxf.fediz.service.idp.spi.TrustedIdpProtocolHandler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class ProtocolSupportValidator implements ConstraintValidator<ProtocolSupported, String> {

    private static final Logger LOG = LoggerFactory.getLogger(ProtocolSupportValidator.class);
    
    @Autowired
    // Qualifier workaround. See http://www.jayway.com/2013/11/03/spring-and-autowiring-of-generic-types/
    @Qualifier("trustedIdpProtocolControllerImpl")
    private ProtocolController<TrustedIdpProtocolHandler> trustedIdpProtocolHandlers;
    
    @Autowired
    @Qualifier("applicationProtocolControllerImpl")
    private ProtocolController<ApplicationProtocolHandler> applicationProtocolHandlers;
    
    
    /*
    public ProtocolSupportValidator() {
        try {
            throw new Exception("test");
        } catch (Exception ex) {
            LOG.error("", ex);
        }
    }
    */
    
    @Override
    public boolean isValid(String object, ConstraintValidatorContext constraintContext) {
        
        
        ConstraintValidatorContextImpl x = (ConstraintValidatorContextImpl)constraintContext;
        Class<?> owner = x.getValidationContext().getCurrentOwner();
        
        List<String> protocols = null;
        if (owner.equals(TrustedIdpEntity.class)) {
            protocols = trustedIdpProtocolHandlers.getProtocols();
        } else if (owner.equals(ApplicationEntity.class)) {
            protocols = applicationProtocolHandlers.getProtocols();
        } else {
            LOG.warn("Invalid owner {}. Ignoring validation.", owner.getCanonicalName());
            return true;
        }
        
        for (String protocol : protocols) {
            if (protocol.equals(object)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void initialize(ProtocolSupported constraintAnnotation) {
    }

}