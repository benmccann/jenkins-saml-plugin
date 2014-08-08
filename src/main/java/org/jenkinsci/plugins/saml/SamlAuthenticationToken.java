/* Licensed to Jenkins CI under one or more contributor license
agreements.  See the NOTICE file distributed with this work
for additional information regarding copyright ownership. 
Jenkins CI licenses this file to you under the Apache License,
Version 2.0 (the "License"); you may not use this file except
in compliance with the License.  You may obtain a copy of the
License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License. */

package org.jenkinsci.plugins.saml;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.AbstractAuthenticationToken;

public class SamlAuthenticationToken extends AbstractAuthenticationToken {

  private static final long serialVersionUID = 1L;

  private final String statusCode;
  private final String issuer;
  private final String audience;
  private final String subject;

  public SamlAuthenticationToken(String statusCode, String issuer, String audience, String subject) {
    super(new GrantedAuthority[] {});
    this.statusCode = statusCode;
    this.issuer = issuer;
    this.audience = audience;
    this.subject = subject;
  }

  public String getStatusCode() {
    return statusCode;
  }

  public String getIssuer() {
    return issuer;
  }

  public String getAudience() {
    return audience;
  }

  public String getSubject() {
    return subject;
  }

  public Object getCredentials() {
    return "SAML does not use passwords";
  }

  public Object getPrincipal() {
    return getSubject();
  }

}
