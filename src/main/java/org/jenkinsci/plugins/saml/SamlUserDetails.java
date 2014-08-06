// Copyright 2014 Connectifier, Inc. All Rights Reserved.

package org.jenkinsci.plugins.saml;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;

public class SamlUserDetails implements UserDetails {

  private static final long serialVersionUID = 1L;

  private final String username;
  
  public SamlUserDetails(String username) {
    this.username = username;
  }

  public GrantedAuthority[] getAuthorities() {
    return new GrantedAuthority [] {};
  }

  public String getPassword() {
    return null;
  }

  public String getUsername() {
    return username;
  }

  public boolean isAccountNonExpired() {
    return true;
  }

  public boolean isAccountNonLocked() {
    return true;
  }

  public boolean isCredentialsNonExpired() {
    return true;
  }

  public boolean isEnabled() {
    return true;
  }

}
