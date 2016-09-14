package cz.mpsv.crypto;

//import java.io.IOException;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
//import java.security.Certificate;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
//import java.security.cert.X509Certificate;
//import java.util.Map;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;


import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.ejb.Local;
import javax.ejb.LocalHome;
import javax.ejb.Remote;
import javax.ejb.RemoteHome;
import javax.ejb.Stateless;
import javax.resource.ResourceException;
import javax.security.auth.login.CredentialException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.axis.AxisFault;
import org.apache.axis.MessageContext;
import org.apache.axis.client.AxisClient;
import org.apache.axis.configuration.NullProvider;
import org.apache.axis.message.SOAPBody;
import org.apache.axis.message.SOAPBodyElement;
import org.apache.axis.message.SOAPEnvelope;
import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.DOM2Writer;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSSecurityEngine;
import org.apache.wss4j.dom.message.WSSecEncrypt;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.message.WSSecTimestamp;
import org.apache.wss4j.dom.util.WSSecurityUtil;
//import org.apache.ws.security.WSConstants;
//import org.apache.ws.security.WSSecurityEngine;
//import org.apache.ws.security.WSSecurityException;
//import org.apache.ws.security.components.crypto.CredentialException;
//import org.apache.ws.security.components.crypto.Crypto;
//import org.apache.ws.security.components.crypto.CryptoFactory;
//import org.apache.ws.security.message.WSEncryptBody;
//import org.apache.ws.security.message.WSSecEncrypt;
//import org.apache.ws.security.message.WSSecHeader;
//import org.apache.ws.security.message.WSSecSignature;
//import org.apache.ws.security.message.WSSecTimestamp;
//import org.apache.ws.security.message.WSSignEnvelope;
//import org.apache.ws.security.util.DOM2Writer;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.sap.aii.af.lib.mp.module.Module;
import com.sap.aii.af.lib.mp.module.ModuleContext;
import com.sap.aii.af.lib.mp.module.ModuleData;
import com.sap.aii.af.lib.mp.module.ModuleException;
import com.sap.aii.af.lib.mp.module.ModuleHome;
import com.sap.aii.af.lib.mp.module.ModuleLocal;
import com.sap.aii.af.lib.mp.module.ModuleLocalHome;
import com.sap.aii.af.lib.mp.module.ModuleRemote;
import com.sap.aii.af.service.resource.SAPSecurityResources;
import com.sap.aii.security.lib.KeyStoreManager;
import com.sap.aii.security.lib.PermissionMode;
import com.sap.engine.interfaces.messaging.api.Message;
import com.sap.engine.interfaces.messaging.api.MessageDirection;
import com.sap.engine.interfaces.messaging.api.MessageKey;
import com.sap.engine.interfaces.messaging.api.PublicAPIAccessFactory;
import com.sap.engine.interfaces.messaging.api.XMLPayload;
import com.sap.engine.interfaces.messaging.api.auditlog.AuditAccess;
import com.sap.engine.interfaces.messaging.api.auditlog.AuditLogStatus;
import com.sap.security.api.ssf.ISsfProfile;
import com.sap.tc.logging.Location;
import com.sun.org.apache.xml.internal.security.encryption.EncryptedData;
import com.sun.org.apache.xml.internal.security.encryption.EncryptedKey;
import com.sun.org.apache.xml.internal.security.encryption.XMLCipher;
import com.sun.org.apache.xml.internal.security.encryption.XMLEncryptionException;
import com.sun.org.apache.xml.internal.security.keys.KeyInfo;

/**
 * Session Bean implementation class CryptoLib
 */
@Stateless(name="CryptoLibBean")
@Local(value={ModuleLocal.class})
@Remote(value={ModuleRemote.class})
@LocalHome(value=ModuleLocalHome.class)
@RemoteHome(value=ModuleHome.class)
public class CryptoLib implements Module{
// nastaveni nazvu parametru na kanalu
	final private String ksViewParamName = "ksView";
	final private String ksUserParamName = "ksUser";
	final private String ksPwdParamName = "pwd";
	
// promenne parametru na kanalu 55222 aa
    private String ksView = "";
    private String ksUser = "";
    private String ksPwd = "";	
	
	// Audit log zpravy
	private AuditAccess audit = null;
	private Location location = null;
	private String direction = "";
	
	private KeyStore ks = null;
	private MessageKey msgKey = null;
	private HashMap keyStores = null;
	
    static {
        //org.apache.xml.security.Init.init();
    	com.sun.org.apache.xml.internal.security.Init.init();
    }	
    
  //init wss4j framework
    private static final WSSecurityEngine secEngine = new WSSecurityEngine();
    
//    private static Crypto crypto = null;
	private AxisClient engine = null;
	private MessageContext msgContext = null;
	
	/**
     * Default constructor. 
     */
    public CryptoLib() {
        // TODO Auto-generated constructor stub
    	keyStores = new HashMap();
    	Properties crProp = new Properties();
    	//crProp.setProperty("org.apache.ws.security.crypto.provider", "org.apache.ws.security.components.crypto.Merlin");
    	//crypto = CryptoFactory.getInstance();
    	//String cryptoProp = properties.getProperty("org.apache.ws.security.saml.issuer.cryptoProp.file");
   }

	@SuppressWarnings("deprecation")
	@Override
	public ModuleData process(ModuleContext moduleContext,
			ModuleData inputModuleData) throws ModuleException {
		String SIGNATURE = "process(ModuleContext moduleContext, ModuleData inputModuleData)@CryptoLib().java";
		//MessageKey msgKey = null;
		
		try {
			location = Location.getLocation(this.getClass().getName());
		} catch (Exception t) {
			t.printStackTrace();
			ModuleException me = new ModuleException(
					"Unable to create trace location", t);
			throw me;
		} 
		
		Message msg = (Message)inputModuleData.getPrincipalData();
		msgKey = msg.getMessageKey();
		audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "Spusten CryptoLib EFFIIS");
		audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "inputModuleData: "+inputModuleData.contentToString());
		
		if (msg.getMessageDirection().equals(MessageDirection.OUTBOUND)) {
//			key = new MessageKey(msg.getMessageId(), MessageDirection.OUTBOUND);
			direction = "OUTPUT";	
		} else {
//			key = new MessageKey(msg.getMessageId(), MessageDirection.INBOUND);
			direction = "INPUT";
		}			
	
		// nacitani dokumentu
		XMLPayload xpld = msg.getDocument();
		String xpldt = xpld.getText();
		audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "xpldt: "+xpldt);
		
		// vytvoreni dokumentu		
		Document docBodyOrig = null;
		try {
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder  dBuilder = dbFactory.newDocumentBuilder();
			docBodyOrig = dBuilder.parse(xpld.getInputStream());
			docBodyOrig.getDocumentElement().normalize();
		} catch (Exception e) {
			audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "Problem reading or parsing payload");
		}	
		
		
		engine = new AxisClient(new NullProvider()); 
		msgContext = new MessageContext(engine);		
		
		//vytvoreni SOAP Hlavicky
		SOAPEnvelope env = new SOAPEnvelope();

		//naplneni puvodniho body do Axis dokumentu
		//SOAPBody axisBody = null;
		Element origDocRoot = docBodyOrig.getDocumentElement();
		SOAPBodyElement axisBodyElement = new SOAPBodyElement(origDocRoot);
		//axisBody.addChildElement(axisBodyElement);
		
		//pridani body do envelope
		env.addBodyElement(axisBodyElement);
		
		//vytvoreni message
		org.apache.axis.Message msgAxis = new org.apache.axis.Message(env);
		
		Document doc = null;
		WSSecHeader secHeader = null;
		try {
			//org.apache.axis.Message msgAxis = new org.apache.axis.Message(xpld.getInputStream());
			
			SOAPEnvelope unsignedSEnvelope = msgAxis.getSOAPEnvelope();
			doc = unsignedSEnvelope.getAsDocument();
		
			secHeader = new WSSecHeader();
			secHeader.insertSecurityHeader(doc);
			
			//add Timestamp
			WSSecTimestamp timestampBuilder = new WSSecTimestamp();
			timestampBuilder.setTimeToLive(300);
			timestampBuilder.prepare(doc);
			timestampBuilder.prependToHeader(secHeader);
		
//		} catch (AxisFault e1) {
//			audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "Problem with Axis (AxisFault): "+e1.getMessage());
//			e1.printStackTrace();
		} catch (Exception e) {
			audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "Problem with Axis (Exception): "+e.getMessage());
			e.printStackTrace();
		}		
		
		ksView = (String) moduleContext.getContextData(ksViewParamName);
		ksUser = (String) moduleContext.getContextData(ksUserParamName);
		ksPwd =  (String) moduleContext.getContextData(ksPwdParamName);
		
		if (ksView.equals("") || ksView == null) {
			location.debugT(SIGNATURE,"ksView parameter is not set.");
			audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "ksView parameter is not set.");
		} else {
			location.debugT(SIGNATURE,"ksView is set to {0}.", new Object[]{ksView});
			audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "ksView is set to {0}.", new Object[]{ksView});			
		}
		
		if (ksUser.equals("") || ksUser == null) {
			location.debugT(SIGNATURE,"ksUser parameter is not set.");
			audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "ksUser parameter is not set.");
		} else {
			location.debugT(SIGNATURE,"ksUser is set to {0}.", new Object[]{ksUser});
			audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "ksUser is set to {0}.", new Object[]{ksUser});			
		}		
		if (ksPwd.equals("") || ksPwd == null) {
			location.debugT(SIGNATURE,"ksPwd parameter is not set.");
			audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "ksPwd parameter is not set.");
		} else {
			location.debugT(SIGNATURE,"ksPwd is set to {0}.", new Object[]{ksPwd});
			audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "ksPwd is set to {0}.", new Object[]{ksPwd});			
		}		

		//inicializace crypto
		EFFIISCrypto crypto = null;
		try {
			crypto = new EFFIISCrypto(ksView, audit, msgKey);
		} catch (KeyStoreException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}	
		
////////////////////////////////
// SIFROVANI WSS4J
////////////////////////////////
/* WSEncryptBody
		WSEncryptBody encryptBody = new WSEncryptBody();
		//X509Certificate[] certs = crypto.getCertificates(ksUser)
		encryptBody.setUserInfo("MS2014_test_public");
		encryptBody.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);
		try {
			Document encryptedDoc = encryptBody.build(doc, crypto);
		} catch (WSSecurityException e) {
			audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "Problem with encryptBody.build: "+e.getMessage());
			e.printStackTrace();
		}
*/

		SecretKey secrKey = null;
		KeyGenerator keyGen = null;
		String sig1Id = "";
		try {
			keyGen = KeyGenerator.getInstance("DESede");
			secrKey = keyGen.generateKey();
			audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "secrKey1: "+secrKey);
		} catch (NoSuchAlgorithmException e) {
			audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "Error KeyGenerator: "+e.getMessage());
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		WSSecEncrypt encrypt = new WSSecEncrypt();
		encrypt.setUserInfo("MS2014_test_public");
		encrypt.setEncKeyId("EncDataMPSV");
		encrypt.setSymmetricKey(secrKey);
		encrypt.setDigestAlgorithm(WSConstants.SHA1);
		//audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "secrKey2: "+secrKey);
		encrypt.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
		encrypt.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);
		encrypt.setKeyEnc(WSConstants.KEYTRANSPORT_RSAOEP);
		try {
			encrypt.build(doc, crypto, secHeader);
//			secrKey = encrypt.getSymmetricKey();
			//audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "secrKey3: "+secrKey);
		} catch (WSSecurityException e) {
			audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "Error during encryption: "+e.getMessage());
			e.printStackTrace();
		}
		
////////////////////////////////
		// Podepisovani 1 WSS4J
		////////////////////////////////		
		
		List<WSEncryptionPart> sig1Parts = new ArrayList<WSEncryptionPart>(2);
		//String soapNamespace = WSSecurityUtil.getSOAPNamespace(doc.getDocumentElement());
		WSEncryptionPart encP = 
            new WSEncryptionPart(
                WSConstants.ELEM_BODY, 
                WSConstants.URI_SOAP11_ENV, 
                ""
            );
        sig1Parts.add(encP);
        encP = null;
        encP = new WSEncryptionPart(
                WSConstants.TIMESTAMP_TOKEN_LN, 
                WSConstants.WSU_NS, 
                ""
            );
        sig1Parts.add(encP);
		
		WSSecSignature sig1Build = new WSSecSignature();
		sig1Build.getWsConfig().setAddInclusivePrefixes(false); //vypnuti inclusiveNamespace
		sig1Build.setSecretKey(secrKey.getEncoded());
		sig1Build.setUserInfo(ksUser, ksPwd); //nevime jestli je potreba
		sig1Build.setKeyIdentifierType(WSConstants.CUSTOM_SYMM_SIGNING);
		sig1Build.setCustomTokenValueType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
		sig1Build.setCustomTokenId("EncDataMPSV");		
		//signer.setCustomTokenId("Sign1Token");
		sig1Build.setDigestAlgo(WSConstants.SHA256);
		sig1Build.setSignatureAlgorithm(WSConstants.HMAC_SHA256);
		//signer.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
		
		try {
			sig1Build.setParts(sig1Parts);
//			signer.addReferencesToSign(sig1Parts, secHeader);
			sig1Build.build(doc, crypto, secHeader);
			sig1Id = sig1Build.getId();
		} catch (WSSecurityException e) {
			audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "Error during signing: "+e.getMessage());
			e.printStackTrace();
		}
		
////////////////////////////////
		// Podepisovani 2 WSS4J
		////////////////////////////////			
		
		List<WSEncryptionPart> sig2Parts = new ArrayList<WSEncryptionPart>(2);
		encP = null;
		encP = new WSEncryptionPart(sig1Id);
		sig2Parts.add(encP);
		
		WSSecSignature sig2Build = new WSSecSignature();
		sig2Build.getWsConfig().setAddInclusivePrefixes(false);
		//sig2Build.setSecretKey(secrKey.getEncoded());
		sig2Build.setUserInfo(ksUser, ksPwd);
		sig2Build.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
		//signer.setCustomTokenId("Sign1Token");
		sig2Build.setDigestAlgo(WSConstants.SHA256);
		sig2Build.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
		//signer.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
		
		try {
			sig2Build.setParts(sig2Parts);
//			signer.addReferencesToSign(sig1Parts, secHeader);
			sig2Build.build(doc, crypto, secHeader);
			//String sig1Id = sig1Build.getId();
		} catch (WSSecurityException e) {
			audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "Error during signing: "+e.getMessage());
			e.printStackTrace();
		}
		
		
		
/*		
////////////////////////////////
// SIFROVANI
////////////////////////////////	
		
// SIFROVANI KLICE		
		String algorithmURI = XMLCipher.RSA_OAEP;
		XMLCipher keyCipher = null;
		PublicKey kek = null;
		SecretKey symmetricKey = null;
		//kek = (PrivateKey) getSecretKey("HmacSHA1", 128);
		//kek = (PrivateKey) getPrivateKey(ksView, ksUser, ksPwd);
		kek = (PublicKey) getPublicKey(ksView, "MS2014_test_public");
		symmetricKey = (SecretKey) getSecretKey("AES", 256);
		audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "PublicKey nacitany: "+symmetricKey);
		audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "PrivateKey nacitany: "+kek);

		try {
			keyCipher = XMLCipher.getInstance(algorithmURI);
		} catch (XMLEncryptionException e) {
			audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "Problem with keyCipher: "+algorithmURI+e.getMessage());
			e.printStackTrace();
		}
		
		try {
			keyCipher.init(XMLCipher.WRAP_MODE, kek);
		} catch (XMLEncryptionException e) {
			audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "Problem with keyCipher.init(): "+algorithmURI+e.getMessage());
			e.printStackTrace();
		}
		
		EncryptedKey encryptedKey = null;
		try {
			encryptedKey = keyCipher.encryptKey(doc, symmetricKey);
		} catch (XMLEncryptionException e) {
			audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "Problem with keyCipher.encryptKey(): "+algorithmURI+e.getMessage());
			e.printStackTrace();
		}
		
// SIFROVANI DAT		
		Element rootElement = doc.getDocumentElement();
		
		algorithmURI = XMLCipher.TRIPLEDES;
		
		XMLCipher xmlCipher = null;
		try {
			xmlCipher = XMLCipher.getInstance(algorithmURI);
		} catch (XMLEncryptionException e) {
			audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "Problem with keyCipher: "+algorithmURI+e.getMessage());
			e.printStackTrace();
		}
		
		try {
			xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetricKey);
		} catch (XMLEncryptionException e) {
			audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "Problem with keyCipher.init(): "+algorithmURI+e.getMessage());
			e.printStackTrace();
		}
		
		EncryptedData encryptedData = xmlCipher.getEncryptedData();
		KeyInfo keyInfo = new KeyInfo(doc);
		try {
			keyInfo.add(encryptedKey);
		} catch (XMLEncryptionException e) {
			e.printStackTrace();
		}
		
		encryptedData.setKeyInfo(keyInfo);
		
		Document outputDoc = null;
		try {
			xmlCipher.doFinal(doc, rootElement, true);
		//	outputDoc = doc;
		} catch (Exception e) {
			e.printStackTrace();
		}
*/
		
		String outputStr = DOM2Writer.nodeToString(doc);
		try {
			
			audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "outputDoc: "+outputStr);
			xpld.setText(outputStr);
			msg.setDocument(xpld);
		} catch (DOMException e) {
			audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "DOMException Problem with setText: "+doc.getTextContent()+e.getMessage());
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return inputModuleData;
		
	}
	
    public static final String prettyPrint(Document xml) throws Exception {
    	Transformer tf = TransformerFactory.newInstance().newTransformer();
    	tf.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
    	tf.setOutputProperty(OutputKeys.INDENT, "yes");
    	Writer out = new StringWriter();
    	tf.transform(new DOMSource(xml), new StreamResult(out));
    	return out.toString();
    }	
	
	@PostConstruct
	public void initialiseResources() {
		//construct any resource here
		try {
			audit = PublicAPIAccessFactory.getPublicAPIAccess().getAuditAccess();
		} catch (Exception e) {
			throw new RuntimeException("error in initialiseResources():"+e.getMessage());
		}
	}
	
	@PreDestroy
	public void ReleaseResources() {
		//release any resources here
	}
	
    /**
     * Get a key from AS Java keystore
     * 
     * @param view
     * @param alias
     * @param password
     * @return
     * @throws ResourceException
     */
    public Key getPrivateKeyOld(KeyStore keystore, String view, String alias, String password) throws ResourceException {
     final String SIGNATURE = "getPrivateKey()";
     location.debugT("Entering: "+ SIGNATURE);
//     KeyStore keystore = getKeystore(view);
     Key privateKey = null;
     try {
         privateKey = (Key) keystore.getKey(alias, password.toCharArray());
         if (privateKey == null) {
          throw new ResourceException("Key not found. alias=" + alias);
         }
     } catch (KeyStoreException e) {
    	 location.errorT("KeyStoreException " + SIGNATURE);
         throw new ResourceException(e);
     } catch (NoSuchAlgorithmException e) {
    	 location.errorT("NoSuchAlgorithmException " + SIGNATURE);
         throw new ResourceException(e);
     } catch (UnrecoverableKeyException e) {
    	 location.errorT("UnrecoverableKeyException " + SIGNATURE);
         throw new ResourceException(e);
     }
     location.debugT("Leaving: "+SIGNATURE);
     return privateKey;
    } 	
	
    public PublicKey getPublicKeyOld(KeyStore keystore, String view, String alias) throws ResourceException {
        final String SIGNATURE = "getPublicKey()";
        location.debugT("Entering: "+SIGNATURE);

//        KeyStore keystore = getKeystore(view);
        PublicKey publicKey = null;
        try {
            publicKey = keystore.getCertificate(alias).getPublicKey();
            if (publicKey == null) {
             throw new ResourceException("Key not found. alias=" + alias);
            }
        } catch (KeyStoreException e) {
        	location.errorT("KeyStoreException " + SIGNATURE);
            throw new ResourceException(e);
        }
        location.debugT("Leaving: "+SIGNATURE);
        return publicKey;

       }      
    
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
    	String SIGNATURE = "getKeystore(String view)@CryptoLib().java";
		location = Location.getLocation(this.getClass().getName());
    	
		KeyStoreManager ksMgr = null;
		KeyStore ks = null;

		if (keyStores.containsKey(view) == true) {
			ks = (KeyStore) keyStores.get(view);
			
		} else {
			try {
				ksMgr = getKeyStoreManager();
				ks = ksMgr.getKeyStore(ksView);
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
    	String SIGNATURE = "getKeyStoreManager()@CryptoLib().java";
		location = Location.getLocation(this.getClass().getName());
    	
		SAPSecurityResources secRes = SAPSecurityResources.getInstance();
		KeyStoreManager ksMgr = null;
		
		try {
			ksMgr = secRes.getKeyStoreManager(PermissionMode.SYSTEM_LEVEL,new String[]{"sap.com/SOAPAdapModuleEJB_cryptoEAR"});
			audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "KeystoreMgr: "+ksMgr.toString());
		} catch (KeyStoreException e) {
			audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "Problem getting KeystoreManager instance (secRes) "+e.getMessage());
			location.errorT(SIGNATURE,"Problem getting KeystoreManager instance (secRes) "+e.getMessage());
			e.printStackTrace();
		}
		
		return ksMgr;
    }
    
    private Key getSecretKey(String algorithm,int arg) {
    	String SIGNATURE = "getSecretKey(String algorithm,int arg)@CryptoLib().java";
			location = Location.getLocation(this.getClass().getName());
		
    	KeyGenerator keyGenerator = null;
    	try {
    		keyGenerator = KeyGenerator.getInstance(algorithm);
    		//keyGenerator.init(arg);
    	} catch (NoSuchAlgorithmException e) {
    		audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "PROBLEM getSecretKey: "+algorithm+" "+e.getMessage());
    	}
    	return keyGenerator.generateKey();
    }
    
    private void skuska() {
    	org.apache.axis.MessageContext pdata =null;

    }
    
///////////////////////
///////////////////////
    ///////////////////
/*
    @Override
	public ModuleData process_zaloha(ModuleContext moduleContext,
			ModuleData inputModuleData) throws ModuleException {
		String SIGNATURE = "process(ModuleContext moduleContext, ModuleData inputModuleData)@CryptoLib().java";
		//MessageKey msgKey = null;
		
		try {
			location = Location.getLocation(this.getClass().getName());
		} catch (Exception t) {
			t.printStackTrace();
			ModuleException me = new ModuleException(
					"Unable to create trace location", t);
			throw me;
		} 
		
		Message msg = (Message)inputModuleData.getPrincipalData();
		msgKey = msg.getMessageKey();
		audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "Spusten CryptoLib EFFIIS");
		
		if (msg.getMessageDirection().equals(MessageDirection.OUTBOUND)) {
//			key = new MessageKey(msg.getMessageId(), MessageDirection.OUTBOUND);
			direction = "OUTPUT";	
		} else {
//			key = new MessageKey(msg.getMessageId(), MessageDirection.INBOUND);
			direction = "INPUT";
		}			
		
		// nacitani dokumentu
		XMLPayload xpld = msg.getDocument();
		String xpldt = xpld.getText();
		audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "xpldt: "+xpldt);
		
		// vytvoreni dokumentu		
		Document doc = null;
		try {
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder  dBuilder = dbFactory.newDocumentBuilder();
			doc = dBuilder.parse(xpld.getInputStream());
			doc.getDocumentElement().normalize();
		} catch (Exception e) {
			audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "Problem reading or parsing payload");
		}		
		
		ksView = (String) moduleContext.getContextData(ksViewParamName);
		ksUser = (String) moduleContext.getContextData(ksUserParamName);
		ksPwd =  (String) moduleContext.getContextData(ksPwdParamName);
		
		if (ksView.equals("") || ksView == null) {
			location.debugT(SIGNATURE,"ksView parameter is not set.");
			audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "ksView parameter is not set.");
		} else {
			location.debugT(SIGNATURE,"ksView is set to {0}.", new Object[]{ksView});
			audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "ksView is set to {0}.", new Object[]{ksView});			
		}
		
		if (ksUser.equals("") || ksUser == null) {
			location.debugT(SIGNATURE,"ksUser parameter is not set.");
			audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "ksUser parameter is not set.");
		} else {
			location.debugT(SIGNATURE,"ksUser is set to {0}.", new Object[]{ksUser});
			audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "ksUser is set to {0}.", new Object[]{ksUser});			
		}		
		if (ksPwd.equals("") || ksPwd == null) {
			location.debugT(SIGNATURE,"ksPwd parameter is not set.");
			audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "ksPwd parameter is not set.");
		} else {
			location.debugT(SIGNATURE,"ksPwd is set to {0}.", new Object[]{ksPwd});
			audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "ksPwd is set to {0}.", new Object[]{ksPwd});			
		}		
	
////////////////////////////////
// SIFROVANI
////////////////////////////////	
		
// SIFROVANI KLICE		
		String algorithmURI = XMLCipher.RSA_OAEP;
		XMLCipher keyCipher = null;
		PublicKey kek = null;
		SecretKey symmetricKey = null;
		//kek = (PrivateKey) getSecretKey("HmacSHA1", 128);
		//kek = (PrivateKey) getPrivateKey(ksView, ksUser, ksPwd);
		kek = (PublicKey) getPublicKey(ksView, "MS2014_test_public");
		symmetricKey = (SecretKey) getSecretKey("AES", 256);
		audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "PublicKey nacitany: "+symmetricKey);
		audit.addAuditLogEntry(msgKey, AuditLogStatus.SUCCESS, "PrivateKey nacitany: "+kek);

		try {
			keyCipher = XMLCipher.getInstance(algorithmURI);
		} catch (XMLEncryptionException e) {
			audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "Problem with keyCipher: "+algorithmURI+e.getMessage());
			e.printStackTrace();
		}
		
		try {
			keyCipher.init(XMLCipher.WRAP_MODE, kek);
		} catch (XMLEncryptionException e) {
			audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "Problem with keyCipher.init(): "+algorithmURI+e.getMessage());
			e.printStackTrace();
		}
		
		EncryptedKey encryptedKey = null;
		try {
			encryptedKey = keyCipher.encryptKey(doc, symmetricKey);
		} catch (XMLEncryptionException e) {
			audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "Problem with keyCipher.encryptKey(): "+algorithmURI+e.getMessage());
			e.printStackTrace();
		}
		
// SIFROVANI DAT		
		Element rootElement = doc.getDocumentElement();
		
		algorithmURI = XMLCipher.TRIPLEDES;
		
		XMLCipher xmlCipher = null;
		try {
			xmlCipher = XMLCipher.getInstance(algorithmURI);
		} catch (XMLEncryptionException e) {
			audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "Problem with keyCipher: "+algorithmURI+e.getMessage());
			e.printStackTrace();
		}
		
		try {
			xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetricKey);
		} catch (XMLEncryptionException e) {
			audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "Problem with keyCipher.init(): "+algorithmURI+e.getMessage());
			e.printStackTrace();
		}
		
		EncryptedData encryptedData = xmlCipher.getEncryptedData();
		KeyInfo keyInfo = new KeyInfo(doc);
		try {
			keyInfo.add(encryptedKey);
		} catch (XMLEncryptionException e) {
			e.printStackTrace();
		}
		
		encryptedData.setKeyInfo(keyInfo);
		
		Document outputDoc = null;
		try {
			xmlCipher.doFinal(doc, rootElement, true);
			outputDoc = doc;
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		try {
			audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "outputDoc: "+prettyPrint(doc));
			xpld.setText(prettyPrint(doc));
			msg.setDocument(xpld);
		} catch (DOMException e) {
			audit.addAuditLogEntry(msgKey, AuditLogStatus.ERROR, "DOMException Problem with setText: "+outputDoc.getTextContent()+e.getMessage());
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return inputModuleData;
		
	}    
	*/
    
}
