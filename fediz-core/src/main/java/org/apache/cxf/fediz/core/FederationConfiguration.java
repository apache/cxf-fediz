/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.cxf.fediz.core;

import java.net.URI;
import java.util.List;
//[TODO]check if we can cache / clone the config 
public class FederationConfiguration {

	private String freshness;
	private String trustedIssuer;
	private String realm;
	private String authenticationType;
	private URI roleURI;
	private String roleDelimiter;
	private String trustStoreFile;
	private String trustStorePassword;
	private List<Class<TokenValidator>> tokenValidators;
	private int maxClockSkew = 0;
	private boolean detectReplayedTokens = true;
	private long tokenReplayCacheExpirationTime = 0;
	private boolean detectExpiredTokens = true;
	
	//[TODO] TokenReplayCacheExpirationPeriod
	//[TODO] DetectReplayedTokens
	
	
	public String getFreshness() {
		return freshness;
	}
	public void setFreshness(String freshness) {
		this.freshness = freshness;
	}
	public String getTrustedIssuer() {
		return trustedIssuer;
	}
	public void setTrustedIssuer(String trustedIssuer) {
		this.trustedIssuer = trustedIssuer;
	}
	public String getRealm() {
		return realm;
	}
	public void setRealm(String realm) {
		this.realm = realm;
	}
	public String getAuthenticationType() {
		return authenticationType;
	}
	public void setAuthenticationType(String authenticationType) {
		this.authenticationType = authenticationType;
	}
	public URI getRoleURI() {
		return roleURI;
	}
	public void setRoleURI(URI roleURI) {
		this.roleURI = roleURI;
	}
	public String getRoleDelimiter() {
		return roleDelimiter;
	}
	public void setRoleDelimiter(String roleDelimiter) {
		this.roleDelimiter = roleDelimiter;
	}
	public List<Class<TokenValidator>> getTokenValidators() {
		return tokenValidators;
	}
	public void setTokenValidators(List<Class<TokenValidator>> tokenValidators) {
		this.tokenValidators = tokenValidators;
	}
	public int getMaxClockSkew() {
		return maxClockSkew;
	}
	public void setMaxClockSkew(int maxClockSkew) {
		this.maxClockSkew = maxClockSkew;
	}
	public boolean isDetectReplayedTokens() {
		return detectReplayedTokens;
	}
	public void setDetectReplayedTokens(boolean detectReplayedTokens) {
		this.detectReplayedTokens = detectReplayedTokens;
	}
	public long getTokenReplayCacheExpirationTime() {
		return tokenReplayCacheExpirationTime;
	}
	public void setTokenReplayCacheExpirationTime(
			long tokenReplayCacheExpirationTime) {
		this.tokenReplayCacheExpirationTime = tokenReplayCacheExpirationTime;
	}
	public boolean isDetectExpiredTokens() {
		return detectExpiredTokens;
	}
	public void setDetectExpiredTokens(boolean detectExpiredTokens) {
		this.detectExpiredTokens = detectExpiredTokens;
	}
	public void setTrustStoreFile(String trustStoreFile) {
		this.trustStoreFile = trustStoreFile;
	}
	public String getTrustStoreFile() {
		return trustStoreFile;
	}
	public void setTrustStorePassword(String trustStorePassword) {
		this.trustStorePassword = trustStorePassword;
	}
	public String getTrustStorePassword() {
		return trustStorePassword;
	}
	
}
