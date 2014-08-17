Jenkins SAML Plugin
===================

A SAML 2.0 Plugin for the Jenkins Continuous Integration server

Usage
-------------------
See the [SAML Plugin page on the Jenkins wiki](https://wiki.jenkins-ci.org/display/JENKINS/SAML+Plugin)

Local development
-------------------

Run `mvn hpi:run` and visit http://localhost:8080/jenkins/.
You will see the plugin under the "Installed" tab in the Jenkins plugin manager.

Releasing
-------------------

Create ~/.m2/settings.xml per https://wiki.jenkins-ci.org/display/JENKINS/Plugin+tutorial and include password as described in https://wiki.jenkins-ci.org/display/JENKINS/Hosting+Plugins.
Run `mvn release:prepare release:perform`
