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
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.opensaml.common.xml.SAMLConstants;
import org.pac4j.core.client.RedirectAction;
import org.pac4j.core.client.RedirectAction.RedirectType;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.context.J2ERequestContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.exception.RequiresHttpAction;
import org.pac4j.saml.client.Saml2Client;
import org.pac4j.saml.credentials.Saml2Credentials;
import org.pac4j.saml.profile.Saml2Profile;

import com.google.common.base.Preconditions;

/**
 * Authenticates the user via SAML.
 * This class is the main entry point to the plugin.
 * Uses Stapler (stapler.kohsuke.org) to bind methods to URLs.
 */
public class SamlSecurityRealm extends SecurityRealm {

  private static final Logger LOG = Logger.getLogger(SamlSecurityRealm.class.getName());
  private static final String REFERER_ATTRIBUTE = SamlSecurityRealm.class.getName() + ".referer";
  private static final String CONSUMER_SERVICE_URL_PATH = "securityRealm/finishLogin";

  private String idpMetadata;

  /**
   * Jenkins passes these parameters in when you update the settings.
   * It does this because of the @DataBoundConstructor
   */
  @DataBoundConstructor
  public SamlSecurityRealm(String signOnUrl, String idpMetadata) {
    super();
    this.idpMetadata = Util.fixEmptyAndTrim(idpMetadata);
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

    Saml2Client client = newClient();
    WebContext context = new J2ERequestContext(request);
    try {
      RedirectAction action = client.getRedirectAction(context, true, false);
      if (action.getType() == RedirectType.REDIRECT) {
        return HttpResponses.redirectTo(action.getLocation());
      } else if (action.getType() == RedirectType.SUCCESS) {
        return HttpResponses.html(action.getContent());
      } else {
        throw new IllegalStateException("Received unexpected response type " + action.getType());
      }
    } catch (RequiresHttpAction e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * /securityRealm/finishLogin
   */
  public HttpResponse doFinishLogin(StaplerRequest request, StaplerResponse response) {
    LOG.finer("SamlSecurityRealm.doFinishLogin called");

    Saml2Client client = newClient();
    WebContext context = new J2EContext(request, response);
    Saml2Credentials credentials;
    try {
      credentials = client.getCredentials(context);
    } catch (RequiresHttpAction e) {
      throw new IllegalStateException(e);
    }
    Saml2Profile saml2Profile = client.getUserProfile(credentials, context);

    SamlAuthenticationToken samlAuthToken = new SamlAuthenticationToken(saml2Profile.getId());
    SecurityContextHolder.getContext().setAuthentication(samlAuthToken);
    SecurityListener.fireAuthenticated(new SamlUserDetails(saml2Profile.getId()));

    String referer = (String) request.getSession().getAttribute(REFERER_ATTRIBUTE);
    String redirectUrl = referer != null ? referer : baseUrl();
    return HttpResponses.redirectTo(redirectUrl);
  }

  private Saml2Client newClient() {
    Preconditions.checkNotNull(idpMetadata);

    Saml2Client client = new Saml2Client();
    client.setIdpMetadata(idpMetadata);
    client.setCallbackUrl(getConsumerServiceUrl());
    client.setDestinationBindingType(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
    return client;
  }

  private String baseUrl() {
    return Jenkins.getInstance().getRootUrl();
  }

  private String getConsumerServiceUrl() {
    return baseUrl() + CONSUMER_SERVICE_URL_PATH;
  }

  public String getIdpMetadata() {
    return idpMetadata;
  }

  public void setIdpMetadata(String idpMetadata) {
    this.idpMetadata = idpMetadata;
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
