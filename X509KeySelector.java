package test;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;


/*
 * 
 * Cette classe est necessaire afin de pouvoir extraire la cle publique du certificat x509
 * 
 * */
public class X509KeySelector extends KeySelector {


	public KeySelectorResult select(KeyInfo keyInfo,
			KeySelector.Purpose purpose,
			AlgorithmMethod method,
			XMLCryptoContext context) throws KeySelectorException {

		Iterator ki = keyInfo.getContent().iterator();
		while (ki.hasNext()) {
			XMLStructure info = (XMLStructure) ki.next();
			if (!(info instanceof X509Data))
				continue;
			X509Data x509Data = (X509Data) info;
			Iterator xi = x509Data.getContent().iterator();
			while (xi.hasNext()) {
				Object o = xi.next();
				if (!(o instanceof X509Certificate))
					continue;
			     return  new CertResult(((X509Certificate)o).getPublicKey());
			}	
			throw new KeySelectorException("pas de cle publique pour l'objet keyInfo");

		 }
	  return null;
	}

	static class CertResult implements KeySelectorResult{
		private PublicKey key;
		public CertResult(PublicKey key){
			this.key=key;
		}
		public Key getKey(){
			return key;

		}
	}




}



