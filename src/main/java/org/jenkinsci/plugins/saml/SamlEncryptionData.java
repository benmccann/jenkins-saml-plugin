package org.jenkinsci.plugins.saml;

import hudson.Util;

import org.kohsuke.stapler.DataBoundConstructor;

/**
 * Simple immutable data class to hold the optional encryption data section
 * of the plugin's configuration page
 */
public class SamlEncryptionData {
  private final String keystorePath;
  private final String keystorePassword;
  private final String privateKeyPassword;

  @DataBoundConstructor
  public SamlEncryptionData(String keystorePath, String keystorePassword, String privateKeyPassword) {
    this.keystorePath = Util.fixEmptyAndTrim(keystorePath);
    this.keystorePassword = Util.fixEmptyAndTrim(keystorePassword);
    this.privateKeyPassword = Util.fixEmptyAndTrim(privateKeyPassword);
  }

  public String getKeystorePath() {
    return keystorePath;
  }

  public String getKeystorePassword() {
    return keystorePassword;
  }

  public String getPrivateKeyPassword() {
    return privateKeyPassword;
  }
}