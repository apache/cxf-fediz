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
package org.apache.cxf.fediz.service.idp;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SessionCacheFilter extends AbstractAuthFilter {

    private static final Logger LOG = LoggerFactory.getLogger(SessionCacheFilter.class);

    protected List<String> cacheAttributes = new ArrayList<String>();
    
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        super.init(filterConfig);
        
        Enumeration enumParams = filterConfig.getInitParameterNames();   
        while (enumParams.hasMoreElements()) {
            String paramName = (String)enumParams.nextElement();
            String paramValue = filterConfig.getInitParameter(paramName);
            if (paramValue != null && paramValue.length() > 0
                && paramName.startsWith("item")) {
                cacheAttributes.add(filterConfig.getInitParameter(paramName));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Attribute '" + paramValue + "' configured to be stored in session.");
                } 
            } else  {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Attribute '" + paramName + "' is ignored, null or empty.");
                }
            }
            
        }
        
    }
    
    @Override
    public void process(HttpServletRequest request,
                        HttpServletResponse response, AuthContext context)
        throws IOException, ServletException, ProcessingException {
        
        if (LOG.isDebugEnabled()) {
            Enumeration e = request.getAttributeNames();
            StringBuffer sb = new StringBuffer();
            sb.append("Cachable attributes:").append(System.getProperty("line.separator"));
            while (e.hasMoreElements()) {
                sb.append((String)e.nextElement()).append(System.getProperty("line.separator"));
            }
            LOG.debug(sb.toString());
        }
        
        for (String item : cacheAttributes) {
            Object value = request.getAttribute(item);
            request.getSession().setAttribute(item, value);
            if (LOG.isInfoEnabled()) {
                LOG.info("Attribute '" + item + "' [" + value + "] stored in session");
            }
        }
        
    }

}
