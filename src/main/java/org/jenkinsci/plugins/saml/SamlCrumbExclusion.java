package org.jenkinsci.plugins.saml;

import java.io.IOException;
import java.util.logging.Logger;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.security.SecurityRealm;
import hudson.security.csrf.CrumbExclusion;

@Extension
public class SamlCrumbExclusion extends CrumbExclusion {
    private static final Logger LOG = Logger.getLogger(SamlCrumbExclusion.class.getName());

    @Override
    public boolean process(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        String pathInfo = request.getPathInfo();
        if(shouldExclude(pathInfo)) {
            return true;
        }
        chain.doFilter(request, response);
        return false;
    }

    private static boolean shouldExclude(String pathInfo) {
        if(pathInfo == null) {
            return false;
        }
        if(pathInfo.indexOf(SamlSecurityRealm.CONSUMER_SERVICE_URL_PATH) == 1) {
            LOG.fine("SamlCrumbExclusion.shouldExclude excluding '" + pathInfo + "'");
            return true;
        } else {
            LOG.fine("SamlCrumbExclusion.shouldExclude keeping '" + pathInfo + "'");
            return false;
        }
    }
}
