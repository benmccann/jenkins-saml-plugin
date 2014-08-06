// Copyright 2014 Connectifier, Inc. All Rights Reserved.

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
