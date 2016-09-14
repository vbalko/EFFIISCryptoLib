package cz.mpsv.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.Properties;
import java.util.regex.Pattern;

import javax.security.auth.callback.CallbackHandler;

//import org.apache.ws.security.WSSecurityException;
//import org.apache.ws.security.components.crypto.AbstractCrypto;
//import org.apache.ws.security.components.crypto.CredentialException;
import org.apache.wss4j.common.crypto.CryptoBase;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;

import com.sap.aii.af.service.resource.SAPSecurityResources;
import com.sap.aii.security.lib.KeyStoreManager;
import com.sap.aii.security.lib.PermissionMode;
import com.sap.engine.interfaces.messaging.api.MessageKey;
import com.sap.engine.interfaces.messaging.api.auditlog.AuditAccess;
import com.sap.engine.interfaces.messaging.api.auditlog.AuditLogStatus;
import com.sap.security.api.ssf.ISsfProfile;
import com.sap.tc.logging.Location;

//public class EFFIISCrypto extends AbstractCrypto {
public class EFFIISCrypto extends CryptoBase {
	
	private Location location = null;
	private AuditAccess audit = null;
	private MessageKey msgKey = null;
	private HashMap keyStores = null;
	private String view = null;
	protected KeyStore keystore = null;
	protected KeyStoreManager manager;
	
	//public EFFIISCrypto(String view, AuditAccess audit, MessageKey msgKey) throws CredentialException,
	public EFFIISCrypto(String view, AuditAccess audit, MessageKey msgKey) throws IOException, KeyStoreException {
		//super(null);
		super();
		
		String SIGNATURE = "EFFIISCrypto(String view, AuditAccess audit, MessageKey msgKey)@EFFIISCrypto.java";
		location = Location.getLocation(this.getClass().getName());
		location.debugT("Entering: "+SIGNATURE);
		
		this.view = view;
		this.audit = audit;
		this.msgKey = msgKey;
		this.keyStores = new HashMap();
		this.manager = getKeyStoreManager();
		//this.keystore = this.manager.getKeyStore(view);
		this.keystore = getKeystore(view);
	}
	
	  public X509Certificate[] getX509Certificates(byte[] data, boolean reverse)
	    throws WSSecurityException
	  {
	    throw new WSSecurityException(null, "getX509Certificates(byte[] data, boolean reverse) not implemented");
	  }	
	
	  public byte[] getCertificateData(boolean reverse, X509Certificate[] certs)
	    throws WSSecurityException
	  {
	    throw new WSSecurityException(null, "getCertificateData(boolean reverse, X509Certificate[] certs) not implemented");
	  }
	  
	  public boolean validateCertPath(X509Certificate[] certs)
	    throws WSSecurityException
	  {
	    throw new WSSecurityException(null, "validateCertPath(X509Certificate[] certs) not implemented");
	  }	  
	  
	    public X509Certificate[] getCertificates(String alias) {
	    	final String SIGNATURE = "getCertificates(String alias)";
	    	location = Location.getLocation(this.getClass().getName());
	    	location.debugT("Entering: "+SIGNATURE);
	    	
			KeyStoreManager ksMgr = null;
			KeyStore ks = null;    	
			X509Certificate[] certificates = null;
	    	
	    	try {
	    		ksMgr = getKeyStoreManager();
	    		ks = getKeystore(this.view);
	    		ISsfProfile pubKeyProf = ksMgr.getISsfProfile(ks, alias, null);
	    		certificates = pubKeyProf.getCertificateChain();
	    	} catch (Exception e) {
				location.errorT(SIGNATURE,"Problem getting CertificatesChain instance. "+e.getMessage());
				audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "Problem getting CertificatesChain instance. "+e.getMessage());
				e.printStackTrace();    		
	    	}
	    	return certificates;		
	    }
	  
//	  public X509Certificate[] getCertificates_orig(String alias)
//	    throws WSSecurityException
//	  {
//		String SIGNATURE = "getCertificates(String alias)@EFFIISCrypto.java";
//		location = Location.getLocation(this.getClass().getName());
//		location.debugT("Entering: "+SIGNATURE);
//		  
//	    X509Certificate[] certificates = null;
//	    try
//	    {
//	      ISsfProfile profile = this.manager.getISsfProfile(this.keystore, alias, null);
//	      if (profile == null) {
//	        throw new WSSecurityException("profile is null");
//	      }
//	      certificates = profile.getCertificateChain();
//	    }
//	    catch (Exception e)
//	    {
//	      throw new WSSecurityException("Unable to retrieve keystore profile", e);
//	    }
//	    return certificates;
//	  }
	  
	  public PrivateKey getPrivateKey(String alias, String password) throws WSSecurityException
	  {
		String SIGNATURE = "getPrivateKey(String alias, String password)@EFFIISCrypto.java";
		location = Location.getLocation(this.getClass().getName());
		location.debugT("Entering: "+SIGNATURE);
		
	    PrivateKey key = null;
	    try
	    {
	      ISsfProfile profile = this.manager.getISsfProfile(this.keystore, alias, null);
	      if (profile == null) {
	        throw new WSSecurityException(null, "profile is null");
	      }
	      key = profile.getPrivateKey();
	    }
	    catch (Exception e)
	    {
			String msg = "Unable to retrieve keystore profile" + e.getMessage();
	    	throw new WSSecurityException(null,msg);
	    }
	    return key;
	  }	  
	  
	  @Override
	  public X509Certificate loadCertificate(InputStream in)
	    throws WSSecurityException               
	  {
	    String SIGNATURE = "loadCertificate(InputStream in)@EFFIISCrypto.java";
		location = Location.getLocation(this.getClass().getName());
		location.debugT("Entering: "+SIGNATURE);
		
	    X509Certificate certificate = null;
	    try
	    {
	    	 CertificateFactory cf = CertificateFactory.getInstance("X.509");
	    	 X509Certificate cert = (X509Certificate)cf.generateCertificate(in);
	      //X509CertificateBinding binding = new X509CertificateBinding(in);	      
	      //certificate = binding.getX509Certificate();
	    }
	    catch (Exception e)
	    {
	      throw new WSSecurityException(null,"Unable to instantiate X509 certificate"+e.getMessage());
	    }
	    return certificate;
	  }	  

		@Override
		public PrivateKey getPrivateKey(X509Certificate arg0, CallbackHandler arg1)
				throws org.apache.wss4j.common.ext.WSSecurityException {
			String SIGNATURE = "getPrivateKey(X509Certificate arg0, CallbackHandler arg1)@EFFIISCrypto.java";
			location = Location.getLocation(this.getClass().getName());
			location.debugT("Entering: "+SIGNATURE);
			
			throw new WSSecurityException(null, "getPrivateKey(X509Certificate arg0, CallbackHandler arg1) not implemented");
		
		}

		@Override
		public X509Certificate[] getX509Certificates(CryptoType cryptoType)
				throws org.apache.wss4j.common.ext.WSSecurityException {
			
			X509Certificate[] certs = null;
			
			switch (cryptoType.getType()){
				case ALIAS: {
					certs = getCertificates(cryptoType.getAlias());
					break;
				}
				default: {
					throw new WSSecurityException(null, "getX509Certificates(CryptoType arg0) not implemented with "+cryptoType);
				}
			}
			return certs;			
		}

		@Override
		public String getX509Identifier(X509Certificate arg0)
				throws org.apache.wss4j.common.ext.WSSecurityException {

			throw new WSSecurityException(null, "getX509Identifier(X509Certificate arg0) not implemented");
		}

		@Override
		public void verifyTrust(PublicKey arg0)
				throws org.apache.wss4j.common.ext.WSSecurityException {
			throw new WSSecurityException(null, "verifyTrust(PublicKey arg0) not implemented");
			
		}

		@Override
		public void verifyTrust(X509Certificate[] arg0, boolean arg1,
				Collection<Pattern> arg2)
				throws org.apache.wss4j.common.ext.WSSecurityException {
			throw new WSSecurityException(null, "verifyTrust(X509Certificate[] arg0, boolean arg1, Collection<Pattern> arg2) not implemented");
			
		}	  
	  
	  
/////////////////////// PRIVATE ////////////////////////	
	
    private PrivateKey getPrivateKey(String view, String alias, String pwd) {
    	final String SIGNATURE = "getPrivateKey(String view, String alias, String pwd)";
    	location = Location.getLocation(this.getClass().getName());
    	
		KeyStoreManager ksMgr = null;
		KeyStore ks = null;    	
    	PrivateKey pKey = null;  
    	
    	try {
    		ksMgr = getKeyStoreManager();
    		ks = getKeystore(view);
    		ISsfProfile privKeyProf = ksMgr.getISsfProfile(ks, alias, pwd);
    		pKey = privKeyProf.getPrivateKey();
    	} catch (Exception e) {
			location.errorT(SIGNATURE,"Problem getting PrivateKey instance. "+e.getMessage());
			audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "Problem getting PrivateKey instance. "+e.getMessage());
			e.printStackTrace();    		
    	}
    	return pKey;
    }
    
    private PublicKey getPublicKey(String view, String alias) {
    	final String SIGNATURE = "getPublicKey()";
    	location = Location.getLocation(this.getClass().getName());
    	
		KeyStoreManager ksMgr = null;
		KeyStore ks = null;    	
    	PublicKey pKey = null;
    	
    	try {
    		ksMgr = getKeyStoreManager();
    		ks = getKeystore(view);
    		ISsfProfile pubKeyProf = ksMgr.getISsfProfile(ks, alias, null);
    		pKey = pubKeyProf.getCertificate().getPublicKey();
    	} catch (Exception e) {
			location.errorT(SIGNATURE,"Problem getting PublicKey instance. "+e.getMessage());
			audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "Problem getting PublicKey instance. "+e.getMessage());
			e.printStackTrace();    		
    	}
    	return pKey;		
    }	
	
    private KeyStore getKeystore(String view) {
    	String SIGNATURE = "getKeystore(String view)@EFFIISCrypto.java";
		location = Location.getLocation(this.getClass().getName());
		location.debugT("Entering: "+SIGNATURE);
    	
		KeyStoreManager ksMgr = null;
		KeyStore ks = null;

		if (keyStores.containsKey(view) == true) {
			ks = (KeyStore) keyStores.get(view);
			
		} else {
			try {
				ksMgr = getKeyStoreManager();
				ks = ksMgr.getKeyStore(view);
				audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "Keystore: "+ks.getType());
				keyStores.put(view, ks);
			} catch (KeyStoreException e) {
				location.errorT(SIGNATURE,"Problem getting Keystore instance (getKeystore) "+e.getMessage());
				audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "Problem getting Keystore instance (getKeystore)"+e.getMessage());
				e.printStackTrace();
			} 
			
		}
		
		return ks;
		
  	
    }	
	
    private KeyStoreManager getKeyStoreManager() {
    	String SIGNATURE = "getKeyStoreManager()@EFFIISCrypto.java";
		location = Location.getLocation(this.getClass().getName());
		location.debugT("Entering: "+SIGNATURE);
    	
		SAPSecurityResources secRes = SAPSecurityResources.getInstance();
		KeyStoreManager ksMgr = null;
		
		try {
			ksMgr = secRes.getKeyStoreManager(PermissionMode.SYSTEM_LEVEL,new String[]{"sap.com/SOAPAdapModuleEJB_cryptoEAR"});
			audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "EFFIISCrypto KeystoreMgr: "+ksMgr.toString());
		} catch (KeyStoreException e) {
			audit.addAuditLogEntry(this.msgKey, AuditLogStatus.ERROR, "EFFIISCrypto Problem getting KeystoreManager instance (secRes) "+e.getMessage());
			location.errorT(SIGNATURE,"Problem getting KeystoreManager instance (secRes) "+e.getMessage());
			e.printStackTrace();
		}
		
		return ksMgr;
    }



}
