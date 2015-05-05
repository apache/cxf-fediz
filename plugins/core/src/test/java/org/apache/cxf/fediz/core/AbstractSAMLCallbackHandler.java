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

package org.apache.cxf.fediz.core;


import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.bean.ActionBean;
import org.apache.wss4j.common.saml.bean.AttributeBean;
import org.apache.wss4j.common.saml.bean.AttributeStatementBean;
import org.apache.wss4j.common.saml.bean.AuthDecisionStatementBean;
import org.apache.wss4j.common.saml.bean.AuthenticationStatementBean;
import org.apache.wss4j.common.saml.bean.ConditionsBean;
import org.apache.wss4j.common.saml.bean.KeyInfoBean;
import org.apache.wss4j.common.saml.bean.KeyInfoBean.CERT_IDENTIFIER;
import org.apache.wss4j.common.saml.bean.SubjectBean;
import org.apache.wss4j.common.saml.bean.SubjectConfirmationDataBean;
import org.apache.wss4j.common.saml.bean.SubjectLocalityBean;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.message.WSSecEncryptedKey;


/**
 * A base implementation of a Callback Handler for a SAML assertion. By default it creates an
 * authentication assertion.
 */
public abstract class AbstractSAMLCallbackHandler implements CallbackHandler {
    
    public enum Statement {
        AUTHN, ATTR, AUTHZ
    };
    
    public enum MultiValue {
        MULTI_VALUE, MULTI_ATTR, ENC_VALUE
    };
    
    public static final URI CLAIM_TYPE_LANGUAGE = 
        URI.create("http://schemas.mycompany.com/claims/language");
    
    protected String subjectName;
    protected String subjectQualifier;
    protected String confirmationMethod;
    protected X509Certificate[] certs;
    protected Statement statement = Statement.AUTHN;
    protected boolean alsoAddAuthnStatement;
    protected CERT_IDENTIFIER certIdentifier = CERT_IDENTIFIER.X509_CERT;
    protected byte[] ephemeralKey;
    protected String issuer;
    protected String subjectNameIDFormat;
    protected String subjectLocalityIpAddress;
    protected String subjectLocalityDnsAddress;
    protected String resource;
    protected List<?> customAttributeValues;
    protected ConditionsBean conditions;
    protected SubjectConfirmationDataBean subjectConfirmationData;
    protected List<String> roles = Arrays.asList("User", "Admin");
    protected Map<String, String> claims;
    protected MultiValue multiValueType = MultiValue.MULTI_VALUE;
    protected String roleSeperator = ",";
    protected String roleAttributeName = FedizConstants.DEFAULT_ROLE_URI.toString();
    protected String countryClaimName = ClaimTypes.COUNTRY.toString();
    protected String customClaimName = CLAIM_TYPE_LANGUAGE.toString();
    protected String attributeNameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified";
    protected boolean useNameFormatAsNamespace;
    
    public void setSubjectConfirmationData(SubjectConfirmationDataBean subjectConfirmationData) {
        this.subjectConfirmationData = subjectConfirmationData;
    }
    
    public void setConditions(ConditionsBean conditionsBean) {
        this.conditions = conditionsBean;
    }
    
    public void setConfirmationMethod(String confMethod) {
        confirmationMethod = confMethod;
    }
    
    public void setStatement(Statement statement) {
        this.statement = statement;
    }
    
    public void setCertIdentifier(CERT_IDENTIFIER certIdentifier) {
        this.certIdentifier = certIdentifier;
    }
    
    public void setCerts(X509Certificate[] certs) {
        this.certs = certs;
    }
    
    public byte[] getEphemeralKey() {
        return ephemeralKey;
    }
    
    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }
    
    public void setSubjectNameIDFormat(String subjectNameIDFormat) {
        this.subjectNameIDFormat = subjectNameIDFormat;
    }
    
    public void setSubjectName(String subjectName) {
        this.subjectName = subjectName;
    }
    
    public void setSubjectLocality(String ipAddress, String dnsAddress) {
        this.subjectLocalityIpAddress = ipAddress;
        this.subjectLocalityDnsAddress = dnsAddress;
    }
    
    public void setResource(String resource) {
        this.resource = resource;
    }
    
    public void setCustomAttributeValues(List<?> customAttributeValues) {
        this.customAttributeValues = customAttributeValues;
    }
    
    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public void setClaims(Map<String, String> claims) {
        this.claims = claims;
    }

    public void setMultiValueType(MultiValue multiValueType) {
        this.multiValueType = multiValueType;
    }
    
    public void setRoleAttributeName(String roleAttributeName) {
        this.roleAttributeName = roleAttributeName;
    }
    
    public String getRoleAttributeName() {
        return this.roleAttributeName;
    }
    
    public void setCountryClaimName(String countryClaimName) {
        this.countryClaimName = countryClaimName;
    }
    
    public String getCountryClaimName() {
        return this.countryClaimName;
    }

    public void setCustomClaimName(String customClaimName) {
        this.customClaimName = customClaimName;
    }
    
    public String getCustomClaimName() {
        return this.customClaimName;
    }

    public void setAttributeNameFormat(String attributeNameFormat) {
        this.attributeNameFormat = attributeNameFormat;
    }
    
    public String getAttributeNameFormat() {
        return this.attributeNameFormat;
    }
    
    public boolean isUseNameFormatAsNamespace() {
        return useNameFormatAsNamespace;
    }

    public void setUseNameFormatAsNamespace(boolean useNameFormatAsNamespace) {
        this.useNameFormatAsNamespace = useNameFormatAsNamespace;
    }

    /**
     * Note that the SubjectBean parameter should be null for SAML2.0
     */
    //CHECKSTYLE:OFF
    protected void createAndSetStatement(SubjectBean subjectBean, SAMLCallback callback) {
        if (alsoAddAuthnStatement || statement == Statement.AUTHN) {
            AuthenticationStatementBean authBean = new AuthenticationStatementBean();
            if (subjectBean != null) {
                authBean.setSubject(subjectBean);
            }
            if (subjectLocalityIpAddress != null || subjectLocalityDnsAddress != null) {
                SubjectLocalityBean subjectLocality = new SubjectLocalityBean();
                subjectLocality.setIpAddress(subjectLocalityIpAddress);
                subjectLocality.setDnsAddress(subjectLocalityDnsAddress);
                authBean.setSubjectLocality(subjectLocality);
            }
            authBean.setAuthenticationMethod("Password");
            callback.setAuthenticationStatementData(Collections.singletonList(authBean));
        }
        
        if (statement == Statement.ATTR) {
            AttributeStatementBean attrStateBean = new AttributeStatementBean();
            if (subjectBean != null) {
                attrStateBean.setSubject(subjectBean);
            }
            
            if (this.roles == null) {
                AttributeBean attributeBean = new AttributeBean();
                if (subjectBean != null) {
                    attributeBean.setSimpleName("name");
                    attributeBean.setQualifiedName("dummy-ns");
                } else {
                    attributeBean.setQualifiedName("dummy-ns");
                }
                attributeBean.addAttributeValue("myvalue");
                attrStateBean.setSamlAttributes(Collections.singletonList(attributeBean));
                callback.setAttributeStatementData(Collections.singletonList(attrStateBean));
                return;
            }
            
            List<AttributeBean> attributeList = new ArrayList<>();
                        
            if (this.multiValueType.equals(MultiValue.MULTI_VALUE)
                || this.multiValueType.equals(MultiValue.ENC_VALUE)) {
//              <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"
//                AttributeNamespace="http://schemas.xmlsoap.org/claims" AttributeName="roles">
//                <saml:AttributeValue>Value1</saml:AttributeValue>
//                <saml:AttributeValue>Value2</saml:AttributeValue>
//              </saml:Attribute>
//                 or                
//              <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"
//              AttributeNamespace="http://schemas.xmlsoap.org/claims" AttributeName="roles">
//              <saml:AttributeValue>Value1,Value2</saml:AttributeValue>
//            </saml:Attribute>
                AttributeBean attributeBean = new AttributeBean();
                if (subjectBean != null) {
                    // SAML 1.1
                    if (this.isUseNameFormatAsNamespace()) {
                        //Workaround for CXF-4484
                        attributeBean.setSimpleName(this.roleAttributeName);
                        //QualifiedName maps to AttributeNamespace in SAML1ComponentBuilder.createSamlv1Attribute()
                        attributeBean.setQualifiedName(ClaimTypes.URI_BASE.toString());
                    } else {
                        attributeBean.setSimpleName(getNameOfClaimType(this.roleAttributeName));
                        //QualifiedName maps to AttributeNamespace in SAML1ComponentBuilder.createSamlv1Attribute()
                        attributeBean.setQualifiedName(getNamespaceOfClaimType(this.roleAttributeName));
                    }
                } else {
                    // SAML 2.0
                    attributeBean.setQualifiedName(this.roleAttributeName);
                    attributeBean.setNameFormat(this.getAttributeNameFormat());
                }
                if (this.multiValueType.equals(MultiValue.MULTI_VALUE)) {
                    for (String role : roles) {
                        attributeBean.addAttributeValue(role);
                    }
                } else {
                    StringBuilder sb = new StringBuilder();
                    for (String role: roles) {
                        sb.append(role).append(this.roleSeperator);
                    }
                    String value = sb.substring(0, sb.length() - this.roleSeperator.length());
                    attributeBean.addAttributeValue(value);
                }
                attributeList.add(attributeBean);
            } else if (this.multiValueType.equals(MultiValue.MULTI_ATTR)) {
//              <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"
//                AttributeNamespace="http://schemas.xmlsoap.org/claims" AttributeName="roles">
//                <saml:AttributeValue>Value1</saml:AttributeValue>
//              </saml:Attribute>
//              <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"
//                AttributeNamespace="http://schemas.xmlsoap.org/claims" AttributeName="roles">
//                <saml:AttributeValue>Value2</saml:AttributeValue>
//              </saml:Attribute>
                
                //List<AttributeBean> attrBeans = new ArrayList<>();
                for (String role: roles) {
                    AttributeBean attributeBean = new AttributeBean();
                    if (subjectBean != null) {
                        // SAML 1.1
                        if (this.isUseNameFormatAsNamespace()) {
                            //Workaround for CXF-4484
                            attributeBean.setSimpleName(this.roleAttributeName);
                            //QualifiedName maps to AttributeNamespace in SAML1ComponentBuilder.createSamlv1Attribute()
                            attributeBean.setQualifiedName(ClaimTypes.URI_BASE.toString());
                        } else {
                            attributeBean.setSimpleName(getNameOfClaimType(this.roleAttributeName));
                            //QualifiedName maps to AttributeNamespace in SAML1ComponentBuilder.createSamlv1Attribute()
                            attributeBean.setQualifiedName(getNamespaceOfClaimType(this.roleAttributeName));
                        }
                    } else {
                        // SAML 2.0
                        attributeBean.setQualifiedName(this.roleAttributeName);
                        attributeBean.setNameFormat(this.getAttributeNameFormat());
                    }
                    attributeBean.addAttributeValue(role);
                    attributeList.add(attributeBean);
                }
            }
            
            //ClaimTypes.COUNTRY
            AttributeBean attributeBean = new AttributeBean();
            if (subjectBean != null) {
                //SAML 1.1
                attributeBean.setSimpleName(getNameOfClaimType(this.countryClaimName));
                //QualifiedName maps to AttributeNamespace in SAML1ComponentBuilder.createSamlv1Attribute()
                attributeBean.setQualifiedName(getNamespaceOfClaimType(this.countryClaimName));
                
            } else {
                //SAML 2.0
                attributeBean.setQualifiedName(this.countryClaimName);
                attributeBean.setNameFormat(this.getAttributeNameFormat());
            }
            attributeBean.addAttributeValue("CH");
            attributeList.add(attributeBean);
            
            //custom claim language
            AttributeBean attributeBean2 = new AttributeBean();
            if (subjectBean != null) {
                // SAML 1.1
                if (this.isUseNameFormatAsNamespace()) {
                    //Workaround for CXF-4484
                    attributeBean2.setSimpleName(this.customClaimName);
                    //QualifiedName maps to AttributeNamespace in SAML1ComponentBuilder.createSamlv1Attribute()
                    attributeBean2.setQualifiedName(ClaimTypes.URI_BASE.toString());
                } else {
                    attributeBean2.setSimpleName(getNameOfClaimType(this.customClaimName));
                    //QualifiedName maps to AttributeNamespace in SAML1ComponentBuilder.createSamlv1Attribute()
                    attributeBean2.setQualifiedName(getNamespaceOfClaimType(this.customClaimName));
                }
            } else {
                // SAML 2
                attributeBean2.setQualifiedName(this.customClaimName);
                attributeBean2.setNameFormat(this.getAttributeNameFormat());
            }
            attributeBean2.addAttributeValue("CH");
            attributeList.add(attributeBean2);
            
            attrStateBean.setSamlAttributes(attributeList);
            callback.setAttributeStatementData(Collections.singletonList(attrStateBean));
                       
        } else if (statement == Statement.AUTHZ) {
            AuthDecisionStatementBean authzBean = new AuthDecisionStatementBean();
            if (subjectBean != null) {
                authzBean.setSubject(subjectBean);
            }
            ActionBean actionBean = new ActionBean();
            actionBean.setContents("Read");
            authzBean.setActions(Collections.singletonList(actionBean));
            authzBean.setResource("endpoint");
            authzBean.setDecision(AuthDecisionStatementBean.Decision.PERMIT);
            authzBean.setResource(resource);
            callback.setAuthDecisionStatementData(Collections.singletonList(authzBean));
        }
    }
    
    protected KeyInfoBean createKeyInfo() throws Exception {
        KeyInfoBean keyInfo = new KeyInfoBean();
        if (alsoAddAuthnStatement || statement == Statement.AUTHN) {
            keyInfo.setCertificate(certs[0]);
            keyInfo.setCertIdentifer(certIdentifier);
        } else if (statement == Statement.ATTR) {
            // Build a new Document
            DocumentBuilderFactory docBuilderFactory = 
                DocumentBuilderFactory.newInstance();
            docBuilderFactory.setNamespaceAware(true);
            DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
            Document doc = docBuilder.newDocument();
                  
            // Create an Encrypted Key
            WSSecEncryptedKey encrKey = new WSSecEncryptedKey();
            encrKey.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
            encrKey.setUseThisCert(certs[0]);
            encrKey.prepare(doc, null);
            ephemeralKey = encrKey.getEphemeralKey();
            Element encryptedKeyElement = encrKey.getEncryptedKeyElement();
            
            // Append the EncryptedKey to a KeyInfo element
            Element keyInfoElement = 
                doc.createElementNS(
                    WSConstants.SIG_NS, WSConstants.SIG_PREFIX + ":" + WSConstants.KEYINFO_LN
                );
            keyInfoElement.setAttributeNS(
                WSConstants.XMLNS_NS, "xmlns:" + WSConstants.SIG_PREFIX, WSConstants.SIG_NS
            );
            keyInfoElement.appendChild(encryptedKeyElement);
            
            keyInfo.setElement(keyInfoElement);
        }
        return keyInfo;
    }
    
    protected String getNamespaceOfClaimType(String claimType) {
        int i = claimType.lastIndexOf("/");
        return claimType.substring(0, i);
    }
    
    protected String getNameOfClaimType(String claimType) {
        int i = claimType.lastIndexOf("/");
        return claimType.substring(i + 1);
    }
    
    public boolean isAlsoAddAuthnStatement() {
        return alsoAddAuthnStatement;
    }

    public void setAlsoAddAuthnStatement(boolean alsoAddAuthnStatement) {
        this.alsoAddAuthnStatement = alsoAddAuthnStatement;
    }
}
