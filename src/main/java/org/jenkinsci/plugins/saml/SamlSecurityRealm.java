// Copyright 2014 Connectifier, Inc. All Rights Reserved.

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
  private static final String CONSUMER_SERVICE_URL = Jenkins.getInstance().getRootUrl() + "securityRealm/finishLogin";

  static final String ISSUER = "Jenkins CI";

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
    LOG.info("SamlSecurityRealm.doCommenceLogin called");
    request.getSession().setAttribute(REFERER_ATTRIBUTE,referer);
    String redirectUrl = new SamlRequestGenerator().createRequestUrl(signOnUrl, CONSUMER_SERVICE_URL);
    return new HttpRedirect(redirectUrl);
  }

  /**
   * /securityRealm/finishLogin
   */
  public HttpResponse doFinishLogin(StaplerRequest request, StaplerResponse response) {
    LOG.info("SamlSecurityRealm.doFinishLogin called");
    Preconditions.checkNotNull(certificate);
    SamlResponseHandler responseHandler = new SamlResponseHandler(certificate);
    SamlAuthenticationToken samlAuthToken = responseHandler.handle(request.getParameter("SAMLResponse"));

    LOG.info("Received SAML response with issuer " + samlAuthToken.getIssuer()
        + " and audience " + samlAuthToken.getAudience());
    Preconditions.checkState(samlAuthToken.getIssuer().equals(ISSUER));

    SecurityContextHolder.getContext().setAuthentication(samlAuthToken);
    SecurityListener.fireAuthenticated(new SamlUserDetails(samlAuthToken.getSubject()));

    String referer = (String) request.getSession().getAttribute(REFERER_ATTRIBUTE);
    return HttpResponses.redirectTo(referer);
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
