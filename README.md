Jenkins SAML Plugin
===================

A SAML 2.0 Plugin for the Jenkins Continuous Integration server

Configuring Jenkins
-------------------

* Go to "Configure Global Security"
* Check "Enable security"
* Select "SAML 2.0"

Configuring Identity Provider (IdP)
-------------------

Example of configuring your IdP such as Okta or OneLogin

 * Postback URL: http://localhost:8080/jenkins/securityRealm/finishLogin
 * Recipient: http://localhost:8080/jenkins/securityRealm/finishLogin
 * Audience Restriction: http://localhost:8080/jenkins/
 * Destination: http://localhost:8080/jenkins/securityRealm/finishLogin


Local development
-------------------

Run `mvn hpi:run` and visit http://localhost:8080/jenkins/.
You will see the plugin under the "Installed" tab in the Jenkins plugin manager.
