// Copyright 2014 Connectifier, Inc. All Rights Reserved.

package org.jenkinsci.plugins.saml;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.codec.binary.Base64;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

public class SamlResponseHandler {

  private final String certificate;

  public SamlResponseHandler(String certificate) {
    this.certificate = certificate;
  }

  public SamlAuthenticationToken handle(String responseMessage) {
    try {
      // Read certificate
      CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      InputStream inputStream = new ByteArrayInputStream(Base64.decodeBase64(certificate.getBytes("UTF-8")));
      X509Certificate x509certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
      inputStream.close();

      BasicX509Credential credential = new BasicX509Credential();
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(x509certificate.getPublicKey().getEncoded());
      PublicKey key = keyFactory.generatePublic(publicKeySpec);
      credential.setPublicKey(key);

      // Parse response
      byte[] base64DecodedResponse = Base64.decodeBase64(responseMessage);

      ByteArrayInputStream is = new ByteArrayInputStream(base64DecodedResponse);
      DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
      documentBuilderFactory.setNamespaceAware(true);
      DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
      Document document = docBuilder.parse(is);
      Element element = document.getDocumentElement();

      UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
      Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
      XMLObject responseXmlObj = unmarshaller.unmarshall(element);
      Response responseObj = (Response) responseXmlObj;
      Assertion assertion = responseObj.getAssertions().get(0);

      Signature sig = assertion.getSignature();
      SignatureValidator validator = new org.opensaml.xml.signature.SignatureValidator(credential);
      validator.validate(sig);
      
      String subject = assertion.getSubject().getNameID().getValue();
      String issuer = assertion.getIssuer().getValue();
      String audience = assertion.getConditions().getAudienceRestrictions().get(0).getAudiences().get(0).getAudienceURI();
      String statusCode = responseObj.getStatus().getStatusCode().getValue();

      return new SamlAuthenticationToken(subject, issuer, audience, statusCode);
    } catch (UnsupportedEncodingException e) {
      throw new IllegalStateException(e);
    } catch (CertificateException e) {
      throw new IllegalStateException(e);
    } catch (ParserConfigurationException e) {
      throw new IllegalStateException(e);
    } catch (SAXException e) {
      throw new IllegalStateException(e);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    } catch (UnmarshallingException e) {
      throw new IllegalStateException(e);
    } catch (ValidationException e) {
      throw new IllegalStateException(e);
    } catch (InvalidKeySpecException e) {
      throw new IllegalStateException(e);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }
}
