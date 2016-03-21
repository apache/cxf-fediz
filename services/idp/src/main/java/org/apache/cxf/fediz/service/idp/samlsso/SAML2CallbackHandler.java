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

package org.apache.cxf.fediz.service.idp.samlsso;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.bean.AttributeBean;
import org.apache.wss4j.common.saml.bean.AttributeStatementBean;
import org.apache.wss4j.common.saml.bean.AuthenticationStatementBean;
import org.apache.wss4j.common.saml.bean.ConditionsBean;
import org.apache.wss4j.common.saml.bean.SubjectBean;
import org.apache.wss4j.common.saml.bean.SubjectConfirmationDataBean;
import org.apache.wss4j.common.saml.bean.Version;
import org.apache.wss4j.common.saml.builder.SAML2Constants;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Subject;

/**
 * A Callback Handler implementation for a SAML 2 assertion. By default it creates a SAML 2.0 Assertion with
 * an AuthenticationStatement. If a list of AttributeStatements are also supplied it will insert them into the
 * Assertion.
 */
public class SAML2CallbackHandler implements CallbackHandler {
    
    private Subject subject;
    private String confirmationMethod = SAML2Constants.CONF_BEARER;
    private String issuer;
    private ConditionsBean conditions;
    private SubjectConfirmationDataBean subjectConfirmationData;
    private List<AttributeStatement> attributeStatements;
    
    private void createAndSetStatement(SAMLCallback callback) {
        AuthenticationStatementBean authBean = new AuthenticationStatementBean();
        authBean.setAuthenticationMethod("Password");
        callback.setAuthenticationStatementData(Collections.singletonList(authBean));

        if (attributeStatements != null && !attributeStatements.isEmpty()) {
            List<AttributeStatementBean> attrStatementBeans = new ArrayList<>();
            
            for (AttributeStatement attrStatement : attributeStatements) {
                AttributeStatementBean attrStatementBean = new AttributeStatementBean();
                List<AttributeBean> attrBeans = new ArrayList<>();
                
                for (Attribute attribute : attrStatement.getAttributes()) {
                    AttributeBean attributeBean = new AttributeBean();
                    attributeBean.setQualifiedName(attribute.getName());
                    attributeBean.setNameFormat(attribute.getNameFormat());
                    List<Object> attributeValues = new ArrayList<>();
                    for (XMLObject attrVal : attribute.getAttributeValues()) {
                        attributeValues.add(attrVal.getDOM().getTextContent());
                    }
                    attributeBean.setAttributeValues(attributeValues);
                    attrBeans.add(attributeBean);
                }
                attrStatementBean.setSamlAttributes(attrBeans);
                attrStatementBeans.add(attrStatementBean);
            }
            callback.setAttributeStatementData(attrStatementBeans);
        }
    }
    
    public void handle(Callback[] callbacks)
        throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof SAMLCallback) {
                SAMLCallback callback = (SAMLCallback) callbacks[i];
                callback.setSamlVersion(Version.SAML_20);
                callback.setIssuer(issuer);
                if (conditions != null) {
                    callback.setConditions(conditions);
                }
                
                SubjectBean subjectBean = 
                    new SubjectBean(
                        subject.getNameID().getValue(), subject.getNameID().getNameQualifier(), confirmationMethod
                    );
                subjectBean.setSubjectNameIDFormat(subject.getNameID().getFormat());
                subjectBean.setSubjectConfirmationData(subjectConfirmationData);

                callback.setSubject(subjectBean);
                createAndSetStatement(callback);
            } else {
                throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
            }
        }
    }
    
    public void setSubjectConfirmationData(SubjectConfirmationDataBean subjectConfirmationData) {
        this.subjectConfirmationData = subjectConfirmationData;
    }
    
    public void setConditions(ConditionsBean conditionsBean) {
        this.conditions = conditionsBean;
    }
    
    public void setConfirmationMethod(String confMethod) {
        confirmationMethod = confMethod;
    }
    
    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public Subject getSubject() {
        return subject;
    }

    public void setSubject(Subject subject) {
        this.subject = subject;
    }

    public List<AttributeStatement> getAttributeStatements() {
        return attributeStatements;
    }

    public void setAttributeStatements(List<AttributeStatement> attributeStatements) {
        this.attributeStatements = attributeStatements;
    }
    
    
}
