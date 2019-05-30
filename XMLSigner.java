package test;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.swing.text.Document;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.xml.sax.SAXException;

public class XMLSigner {
	
	private  static final String digestMethodURI ="http://www.w3.org/2000/09/xmldsig#sha1";
	private  static final String transformURI = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
	private  static final String signatureMethodURI = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

	private String xmlFilename;
	private XMLSignatureFactory factory;
	private KeyStore.PrivateKeyEntry keyEntry ;
	private SignedInfo signedInfo;
	private KeyInfo keyInfo;
	


	
	public XMLSigner(String xmlFilename) throws FileNotFoundException{

		if (!Files.exists(Paths.get(xmlFilename))){
			throw new FileNotFoundException();
		}
		else {
			this.xmlFilename=xmlFilename;
			prepare();
			load_key();

		}


	}


	private void prepare() {
		Reference ref = null;
		factory = XMLSignatureFactory.getInstance("DOM");

		try{
			// we want to sign the content of the root element 
			ref = factory.newReference
					("", factory.newDigestMethod(digestMethodURI, null),
							Collections.singletonList
							(factory.newTransform(transformURI, (TransformParameterSpec) null)), null, null);


			 signedInfo = factory.newSignedInfo
					(factory.newCanonicalizationMethod
							(CanonicalizationMethod.INCLUSIVE,
									(C14NMethodParameterSpec) null),
							factory.newSignatureMethod(signatureMethodURI, null),
							Collections.singletonList(ref));

		}catch(GeneralSecurityException e){
			System.out.println(e.getMessage());

		}

	}

	
	
	
	
	private void load_key() {
		X509Certificate certificat = null;
		try{
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(new FileInputStream("ImportKey"), "importkey".toCharArray());
			keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry
					("importkey", new KeyStore.PasswordProtection("importkey".toCharArray()));
			certificat = (X509Certificate) keyEntry.getCertificate();
		}catch(GeneralSecurityException | IOException e){
			System.out.println(e.getMessage());
		}
		
		KeyInfoFactory keyInfoFactory = factory.getKeyInfoFactory();
		List x509Content = new ArrayList();
		x509Content.add(certificat.getSubjectX500Principal().getName());
		x509Content.add(certificat);
		X509Data x509data = keyInfoFactory.newX509Data(x509Content);
	    keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(x509data));
	}

	
	
	
	
	
	
	public void sign() {
		
		org.w3c.dom.Document document = null;
		
		DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
		builderFactory.setNamespaceAware(true);
		DocumentBuilder builder;
		try {
			builder = builderFactory.newDocumentBuilder();
			document = builder.parse(new FileInputStream(xmlFilename));
			DOMSignContext context = new DOMSignContext(keyEntry.getPrivateKey(), document.getDocumentElement());
			XMLSignature signature = factory.newXMLSignature(signedInfo, keyInfo);
			signature.sign(context);
		} catch (ParserConfigurationException | SAXException | IOException | MarshalException | XMLSignatureException e) {
			
				System.out.println(e.getMessage());
	
		}
	
		try {

			OutputStream os = new FileOutputStream(xmlFilename+".signed");
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer trans = tf.newTransformer();
			trans.transform(new DOMSource(document), new StreamResult(os));
		} catch (TransformerException | FileNotFoundException e) {
			
			e.printStackTrace();
		}
		
	}



}
