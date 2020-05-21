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

import java.io.StringWriter;

import javax.xml.XMLConstants;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Element;

import org.apache.commons.text.StringEscapeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.webflow.execution.RequestContext;

/**
 * Serialize the RP Token
 */
@Component
public class TokenSerializer {

    private static final Logger LOG = LoggerFactory.getLogger(TokenSerializer.class);

    public String serialize(RequestContext context, Element rpToken) {
        if (rpToken != null) {
            StringWriter sw = new StringWriter();
            try {
                TransformerFactory tf = TransformerFactory.newInstance();
                tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
                try {
                    tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
                    tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
                } catch (IllegalArgumentException ex) {
                    // ignore
                }

                Transformer t = tf.newTransformer();
                t.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
                t.transform(new DOMSource(rpToken), new StreamResult(sw));
            } catch (TransformerException te) {
                LOG.warn("nodeToString Transformer Exception");
            }
            String serializedToken = sw.toString();

            return StringEscapeUtils.escapeXml11(serializedToken);
        }

        return null;
    }
}
