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
package org.apache.cxf.fediz.service.idp.beans;

import java.util.Map;

import org.apache.cxf.fediz.service.idp.domain.Idp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.RequestContext;

/**
 * Check the size of the parameters against the default value. "wresult", "SAMLRequest" and "SAMLResponse"
 * are excluded from the check.
 */
@Component
public class ParameterSizeChecker {

    private static final Logger LOG = LoggerFactory.getLogger(ParameterSizeChecker.class);

    public boolean submit(Idp idp, RequestContext context) {
        int maxParameterSize = idp.getMaxParameterSize();

        if (!context.getRequestParameters().isEmpty()) {
            Map<String, Object> parameters = context.getRequestParameters().asMap();
            for (Map.Entry<String, Object> param : parameters.entrySet()) {
                if (!skipCheck(param.getKey()) && param.getValue() != null
                    && param.getValue().toString().length() > maxParameterSize) {
                    LOG.debug("The " + param.getKey() + " parameter size " + param.getValue().toString().length()
                              + " exceeds the maximum allowed value of " + maxParameterSize);
                    return false;
                }
            }
        }

        return true;
    }

    private boolean skipCheck(String parameter) {
        return "wresult".equals(parameter) || "SAMLRequest".equals(parameter)
            || "SAMLResponse".equals(parameter);
    }
}
