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

import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.security.SecurityRealm;

import java.util.logging.Logger;

import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.context.SecurityContextHolder;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

import com.google.common.base.Preconditions;

/**
 * Authenticates the user via SAML.
 * This class is the main entry point to the plugin.
 * Uses Stapler (stapler.kohsuke.org) to bind methods to URLs.
 */
public class SamlSecurityRealm extends SecurityRealm {

  private static final Logger LOG = Logger.getLogger(SamlSecurityRealm.class.getName());
  private static final String REFERER_ATTRIBUTE = SamlSecurityRealm.class.getName()+".referer";
  private static final String CONSUMER_SERVICE_URL_PATH = "securityRealm/finishLogin";

  private String signOnUrl;

  private String certificate;

  /**
   * Jenkins passes these parameters in when you update the settings.
   * It does this because of the @DataBoundConstructor
   */
  @DataBoundConstructor
  public SamlSecurityRealm(String signOnUrl, String certificate) {
    super();
    this.signOnUrl = Util.fixEmptyAndTrim(signOnUrl);
    this.certificate = Util.fixEmptyAndTrim(certificate);
  }

  @Override
  public boolean allowsSignup() {
    return false;
  }

  @Override
  public SecurityComponents createSecurityComponents() {

    return new SecurityComponents(new AuthenticationManager() {

      public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication instanceof SamlAuthenticationToken) {
          return authentication;
        }
        throw new BadCredentialsException("Unexpected authentication type: " + authentication);
      }

    });
  }

  @Override
  public String getLoginUrl() {
    return "securityRealm/commenceLogin";
  }

  /**
   * /securityRealm/commenceLogin
   */
  public HttpResponse doCommenceLogin(StaplerRequest request, @Header("Referer") final String referer) {
    LOG.fine("SamlSecurityRealm.doCommenceLogin called. Using consumerServiceUrl " + getConsumerServiceUrl());
    request.getSession().setAttribute(REFERER_ATTRIBUTE, referer);
    String redirectUrl = new SamlRequestGenerator()
        .createRequestUrl(signOnUrl, getConsumerServiceUrl(), Jenkins.getInstance().getRootUrl());
    return new HttpRedirect(redirectUrl);
  }

  /**
   * /securityRealm/finishLogin
   */
  public HttpResponse doFinishLogin(StaplerRequest request, StaplerResponse response) {
    LOG.finer("SamlSecurityRealm.doFinishLogin called");
    Preconditions.checkNotNull(certificate);
    SamlResponseHandler responseHandler = new SamlResponseHandler(certificate);
    SamlAuthenticationToken samlAuthToken = responseHandler.handle(request.getParameter("SAMLResponse"));

    LOG.info("Received SAML response with status code " + samlAuthToken.getStatusCode()
        + ", subject " + samlAuthToken.getSubject()
        + ", issuer " + samlAuthToken.getIssuer()
        + ", audience " + samlAuthToken.getAudience());

    Preconditions.checkState(samlAuthToken.getStatusCode().toLowerCase().contains("success"),
        "Expected success but got " + samlAuthToken.getStatusCode());

    SecurityContextHolder.getContext().setAuthentication(samlAuthToken);
    SecurityListener.fireAuthenticated(new SamlUserDetails(samlAuthToken.getSubject()));

    String referer = (String) request.getSession().getAttribute(REFERER_ATTRIBUTE);
    return HttpResponses.redirectTo(referer);
  }

  private String getConsumerServiceUrl() {
    return Jenkins.getInstance().getRootUrl() + CONSUMER_SERVICE_URL_PATH;
  }
  
  public String getSignOnUrl() {
    return signOnUrl;
  }

  public void setSignOnUrl(String signOnUrl) {
    this.signOnUrl = signOnUrl;
  }

  public String getCertificate() {
    return certificate;
  }

  public void setCertificate(String certificate) {
    this.certificate = certificate;
  }

  @Extension
  public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

    public DescriptorImpl() {
      super();
    }

    public DescriptorImpl(Class<? extends SecurityRealm> clazz) {
      super(clazz);
    }

    @Override
    public String getDisplayName() {
      return "SAML 2.0";
    }

  }

}
