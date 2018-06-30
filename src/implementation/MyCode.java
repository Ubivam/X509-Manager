package implementation;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GuardedObject;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;
import javax.swing.SpringLayout.Constraints;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;

import java.security.*;
import java.security.KeyStore.*;
import java.security.cert.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.time.chrono.IsoChronology;

import code.GuiException;
import code.X509;
import gui.Constants;
import x509.v3.CodeV3;

public class MyCode extends CodeV3 {
	private static String localKeyStoreFile = "localKeyStore.p12";

	private static String localKeyStorePassword = "root";
	private static String entyPassword = "root";

	private static final String BASIC_CONSTRAINS = "2.5.29.19";
	private static final String CERTIFICATE_POLICIES = "2.5.29.32";
	private static final String ISSUER_ALTERNATIVE_NAME = "2.5.29.18";

	private KeyStore localKeyStore;
	private PKCS10CertificationRequest csr = null;
	private X509Certificate cert = null;

	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
		super(algorithm_conf, extensions_conf, extensions_rules);
		Security.addProvider(new BouncyCastleProvider());
	}

	@Override
	public boolean canSign(String keypair_name) {
		X509Certificate certificate = (X509Certificate) find();
		if (certificate.getBasicConstraints() != -1) {
			return true;
		}
		return false;
	}

	@Override
	public boolean exportCSR(String file, String keypair_name, String algorithm) {

		try {
			X509Certificate certificate = (X509Certificate) localKeyStore.getCertificate(keypair_name);
			ExtensionsGenerator extGen = new ExtensionsGenerator();
			X509CertificateHolder holder = new JcaX509CertificateHolder(certificate);
			HashSet<Object> set = new HashSet<>();

			Extensions extensions = holder.getExtensions();
			if (extensions != null) {
				Enumeration e = extensions.oids();

				while (e.hasMoreElements()) {
					ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) e.nextElement();
					Extension ext = extensions.getExtension(oid);
					extGen.addExtension((Extension) ext);
					set.add(oid.getId());
				}
			}
			PublicKey pub = certificate.getPublicKey();
			PrivateKey pr = ((PrivateKey) localKeyStore.getKey(keypair_name, entyPassword.toCharArray()));
			if (pr == null)
				System.out.println("******************************");
			PKCS10CertificationRequestBuilder p10ReqBuilder = new JcaPKCS10CertificationRequestBuilder(
					new X500Name(certificate.getSubjectX500Principal().getName()), pub);
			p10ReqBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());

			JcaContentSignerBuilder signer = new JcaContentSignerBuilder(algorithm);
			ContentSigner cs = signer
					.build((PrivateKey) localKeyStore.getKey(keypair_name, entyPassword.toCharArray()));

			csr = p10ReqBuilder.build(cs);

			File f = new File(file);
			FileWriter fw = new FileWriter(f);

			JcaPEMWriter pemWriter = new JcaPEMWriter(fw);
			pemWriter.writeObject(csr);
			pemWriter.close();
			return true;
		} catch (OperatorCreationException | CertificateEncodingException | UnrecoverableKeyException
				| NoSuchAlgorithmException | KeyStoreException | IOException e) {
			e.printStackTrace();
			csr = null;
			return false;
		}

	}

	@Override
	public boolean exportCertificate(String file, String keypair_name, int encoding, int format) { // DODAJ CHAIN
		File f = new File(file);
		try {
			if (Files.isDirectory(Paths.get(f.getAbsolutePath())))
				return false;
			FileOutputStream outPutStream;
			if (f.getName().length() < 4 || !f.getName().substring(f.getName().length() - 4).equals(".cer")) {
				outPutStream = new FileOutputStream(f + ".cer", true);
			} else {
				outPutStream = new FileOutputStream(f, true);
			}
			Certificate certificate = find();
			if (encoding == Constants.PEM) {
				OutputStreamWriter writer = new OutputStreamWriter(outPutStream);
				JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
				if (format == 0) {
					pemWriter.writeObject(certificate);
				} else {
					Certificate[] chain = find_chain();
					pemWriter.writeObject(chain);
				}
				pemWriter.close();
				writer.close();
			} else {
				outPutStream.write(certificate.getEncoded());
			}
			outPutStream.close();
			return true;
		} catch (CertificateEncodingException | IOException e) {
			e.printStackTrace();
			return false;
		}

	}

	@Override
	public boolean exportKeypair(String keypair_name, String file, String password) {
		// TODO Auto-generated method stub
		KeyStore ks;
		if (!file.contains(".p12")) {
			file += ".p12";
		}
		try {
			ks = KeyStore.getInstance("PKCS12");
			if (!new File(file).exists()) {
				ks.load(null, null);
			} else {
				ks.load(new FileInputStream(file), password.toCharArray());
			}

			Key key = localKeyStore.getKey(keypair_name, entyPassword.toCharArray());
			if (key instanceof PrivateKey) {
				Certificate certificate = localKeyStore.getCertificate(keypair_name);
				Certificate[] chain = localKeyStore.getCertificateChain(keypair_name);
				ks.setKeyEntry(keypair_name, key, entyPassword.toCharArray(), chain);
				ks.store(new FileOutputStream(file), password.toCharArray());
				return true;
			}
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException
				| UnrecoverableKeyException e) {
			e.printStackTrace();
			return false;
		}
		return false;
	}

	@Override
	public String getCertPublicKeyAlgorithm(String keypair_name) {
		try {
			return ((X509Certificate) localKeyStore.getCertificate(keypair_name)).getPublicKey().getAlgorithm();
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public String getCertPublicKeyParameter(String keypair_name) { // POGLEDAJ OVDE!!!
		try {
			return Integer.toString((((RSAPublicKey) localKeyStore.getCertificate(keypair_name).getPublicKey())
					.getModulus().bitLength()));
		} catch (KeyStoreException e) {
			// TODO: handle exception
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public String getSubjectInfo(String keypair_name) { // Treba dorada verv
		try {
			X509Certificate certificate = (X509Certificate) localKeyStore.getCertificate(keypair_name);
			JcaX509CertificateHolder holder = new JcaX509CertificateHolder(certificate);
			return holder.getSubject().toString();
		} catch (CertificateEncodingException | KeyStoreException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public boolean importCAReply(String file, String keypair_name) {
		try {
			InputStream is = new FileInputStream(file);
			// ASN1OutputStream asn1 = new ASN1InputStream(sigData.getEncoded())
			ASN1InputStream asn1 = new ASN1InputStream(is);
			CMSSignedData s = new CMSSignedData(asn1);
			Store<X509CertificateHolder> certStore = s.getCertificates();
			SignerInformationStore signers = s.getSignerInfos();
			Collection<SignerInformation> c = signers.getSigners();
			// Iterator it = c.iterator();
			// while (it.hasNext()) {
			// SignerInformation signer = (SignerInformation) it.next();
			// Collection certCollection = certStore.getMatches(signer.getSID());

			// Iterator certIt = certCollection.iterator();
			// X509CertificateHolder cert = (X509CertificateHolder) certIt.next();
			ArrayList<X509CertificateHolder> listCertDatFirm = new ArrayList<X509CertificateHolder>(
					certStore.getMatches(null));
			Certificate[] chain = new Certificate[listCertDatFirm.size()];
			for (int i = 0; i < listCertDatFirm.size(); i++) {
				X509CertificateHolder holder = listCertDatFirm.get(i);
				X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC")
						.getCertificate(holder);
				chain[i] = (Certificate) certificate;
			}
			// if (signer.verify(new
			// JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert))) {
			PrivateKey privateKey = (PrivateKey) localKeyStore.getKey(keypair_name,
					localKeyStorePassword.toCharArray());
			// PrivateKey privateKey = (PrivateKey) s.getSignedContent();
			localKeyStore.deleteEntry(keypair_name);
			localKeyStore.setKeyEntry(keypair_name, privateKey, localKeyStorePassword.toCharArray(), chain);
			localKeyStore.store(new FileOutputStream(localKeyStoreFile), localKeyStorePassword.toCharArray());
			loadKeypair(keypair_name);

			// }
			// }
			return true;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	@SuppressWarnings("resource")
	@Override
	public String importCSR(String file) {
		File f = new File(file);
		try {
			if (!f.exists())
				return null;
			InputStream is = new FileInputStream(f);
			InputStreamReader isReader = new InputStreamReader(is);
			PEMParser pr = new PEMParser(isReader);
			PKCS10CertificationRequest signRequest = (PKCS10CertificationRequest) pr.readObject();
			ContentVerifierProvider prov = new JcaContentVerifierProviderBuilder()
					.build(signRequest.getSubjectPublicKeyInfo());
			if (!signRequest.isSignatureValid(prov)) {
				throw new CryptoException("Not Veryfied CSR!");
			}
			csr = signRequest;
			String alg = null;
			if (signRequest.getSignatureAlgorithm().getAlgorithm().toString().compareTo("1.2.840.113549.1.1.5") == 0) {
				alg = "SHA1withRSA";
			}
			if (signRequest.getSignatureAlgorithm().getAlgorithm().toString().compareTo("1.2.840.113549.1.1.11") == 0) {
				alg = "SHA256withRSA";
			}
			if (signRequest.getSignatureAlgorithm().getAlgorithm().toString().compareTo("1.2.840.113549.1.1.12") == 0) {
				alg = "SHA384withRSA";
			}
			if (signRequest.getSignatureAlgorithm().getAlgorithm().toString().compareTo("1.2.840.113549.1.1.13") == 0) {
				alg = "SHA512withRSA";
			}

			if (alg == null)
				return null;
			// System.out.println((signRequest.getSubject().toString() + ",SA=" +
			// signRequest.getSignatureAlgorithm().toString()));
			return (signRequest.getSubject().toString() + ",SA=" + alg);
		} catch (CryptoException | PKCSException | OperatorCreationException | IOException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public boolean importCertificate(String file, String keypair_name) {
		// TODO Auto-generated1 method stub
		File f = new File(file);
		try {
			if (!f.exists())
				return false;
			InputStream is = new FileInputStream(f);
			CertificateFactory factory = CertificateFactory.getInstance("X509");
			List<Certificate> lc = new ArrayList<Certificate>();
			while (is.available() > 0) {
				X509Certificate certificate = (X509Certificate) factory.generateCertificate(is);
				lc.add(certificate);
			}
			localKeyStore.setCertificateEntry(keypair_name, lc.get(lc.size() - 1));
			is.close();
			return true;
		} catch (KeyStoreException | CertificateException | IOException e) {
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public boolean importKeypair(String keypair_name, String file, String password) {
		try {
			FileInputStream fis = new FileInputStream(file);
			KeyStore ks = KeyStore.getInstance("PKCS12");
			ks.load(fis, password.toCharArray());

			Key key = ks.getKey(keypair_name, password.toCharArray());
			if (key instanceof PrivateKey) {
				Certificate certificate = ks.getCertificate(keypair_name);
				PublicKey publicKey = certificate.getPublicKey();
				KeyPair keyPair = new KeyPair(publicKey, (PrivateKey) key);
				Certificate[] chain = ks.getCertificateChain(keypair_name);
				localKeyStore.setKeyEntry(keypair_name, key, entyPassword.toCharArray(), chain);
				localKeyStore.store(new FileOutputStream(localKeyStoreFile), localKeyStorePassword.toCharArray());
				return true;
			}

		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException
				| UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return false;
	}

	@Override

	// Ova metoda se pokrece selektovanjem bilo kog para
	// kljuceva/sertifikata u listi aliasa Local KeyStore
	// Ova metoda treba da ocita podatke o paru kljuceva/
	// sertifikata koji je sacuvan pod aliason keypair_name
	// iz lokalnog skladista sertifikata i pokaze ih na grafickom
	// korisnickom interfejsu pomocu metoda get/set GUI interfejsa
	// metoda vraca -1 u slucaju greske, 0 u slucaju da sertifikat
	// sacuvan pod tim alijasom nije potpisan, 1 u slucaju da je
	// potpisan, 2 u slucaju da je u pitanju trusted sertifikat

	public int loadKeypair(String keypair_name) {
		int ret = -1;
		try {
			// containsAlias proverava da li zadati alijas
			// postoji u keystoru
			if (localKeyStore.containsAlias(keypair_name)) {
				X509Certificate certificate = (X509Certificate) localKeyStore.getCertificate(keypair_name);
				if (certificate.getBasicConstraints() != -1) {
					ret = 2;
				} else {
					Certificate[] chain = localKeyStore.getCertificateChain(keypair_name);

					try {
						if (chain.length == 1) {
							certificate.verify(certificate.getPublicKey());
							ret = 0;
						} else {
							certificate.verify(chain[1].getPublicKey());
							ret = 1;
						}
					} catch (CertificateException | NoSuchAlgorithmException | SignatureException e) {
						e.printStackTrace();
						ret = 0;
					}
				}
				System.out.println(certificate.getSigAlgName());
				JcaX509CertificateHolder holder = new JcaX509CertificateHolder(certificate);
				X500Name subject = holder.getSubject();
				X500Name issuer = holder.getIssuer();
				if (issuer != null) {
					super.access.setIssuer(issuer.toString());
					super.access.setIssuerSignatureAlgorithm(certificate.getSigAlgName());
				}
				super.access.setSubject(subject.toString());
				super.access.setPublicKeyAlgorithm(certificate.getSigAlgName());
				super.access.setSerialNumber(certificate.getSerialNumber().toString());
				super.access.setNotBefore(certificate.getNotBefore());
				super.access.setNotAfter(certificate.getNotAfter());
				super.access.setVersion(certificate.getVersion() - 1);
				super.access.setSubjectSignatureAlgorithm(certificate.getSigAlgName());
				System.out.println(certificate.toString());

				// EXTENSIONS
				Set<String> critSet = certificate.getCriticalExtensionOIDs();

				if (critSet != null && !critSet.isEmpty()) {
					System.out.println("Set of critical extensions: ");
					for (String oid : critSet) {
						// -------------------------------BC------------------------------------------
						if (oid.equals(BASIC_CONSTRAINS) && certificate.getBasicConstraints() != -1) {
							access.setCritical(Constants.BC, true);
							access.setCA(true);
							Integer pathLength = certificate.getBasicConstraints();
							access.setPathLen(pathLength.toString());
							System.out.println("[BC]:" + pathLength.toString() + "\n");
						}
						// ---------------------IAN-----------------------------------
						List<String> subjectAltList = new ArrayList<String>();
						Collection<List<?>> altNames = certificate.getIssuerAlternativeNames();
						if (altNames != null) {
							Iterator<List<?>> it = altNames.iterator();
							List list;
							while (it.hasNext()) {
								list = it.next();
								String alterName = (String) list.get(1);
								subjectAltList.add(alterName);
							}
							super.access.setCritical(Constants.IAN, true);
							super.access.setAlternativeName(Constants.IAN, subjectAltList.toString());
							System.out.println("[IAN]:" + subjectAltList.toString());
						}
						// ----------------------CP-----------------------------------------------

						super.access.setCritical(Constants.CP, true); // TODO the rest!
						byte[] policyBytes = certificate.getExtensionValue(Extension.certificatePolicies.toString());
						if (policyBytes != null) {
							CertificatePolicies policies = CertificatePolicies
									.getInstance(X509ExtensionUtil.fromExtensionValue(policyBytes));
							PolicyInformation[] policyInformation = policies.getPolicyInformation();
							for (PolicyInformation pInfo : policyInformation) {
								ASN1Sequence policyQualifiers = (ASN1Sequence) pInfo.getPolicyQualifiers()
										.getObjectAt(0);
								super.access.setCpsUri(policyQualifiers.getObjectAt(1).toString());
							}
							super.access.setAnyPolicy(true);
						}
					}

				}

			}
		} catch (NoSuchProviderException | KeyStoreException | CertificateException | InvalidKeyException | IOException e) {
			e.printStackTrace();
			return -1;
		}
		return ret;
	}

	@Override
	public Enumeration<String> loadLocalKeystore() {
		try {
			localKeyStore = KeyStore.getInstance("PKCS12");
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		File f = new File(localKeyStoreFile);
		if (!f.exists()) {
			try {
				localKeyStore.load(null, null);
				localKeyStore.store(new FileOutputStream(localKeyStoreFile), localKeyStorePassword.toCharArray());
				return null;
			} catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e) {
				e.printStackTrace();
			}
		}

		FileInputStream fis = null;
		try {
			fis = new FileInputStream(localKeyStoreFile);
			localKeyStore.load(fis, localKeyStorePassword.toCharArray());
			Enumeration<String> alias = localKeyStore.aliases();
			if (!alias.hasMoreElements()) {
				return null;
			}
			return alias;
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (fis != null) {
				try {
					fis.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		return null;
	}

	@Override
	public boolean removeKeypair(String keypair_name) {
		try {
			if (localKeyStore.containsAlias(keypair_name)) {
				localKeyStore.deleteEntry(keypair_name);
				return true;
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public void resetLocalKeystore() {
		new File(localKeyStoreFile).delete();
		try {
			localKeyStore = KeyStore.getInstance("PKCS12");
			localKeyStore.load(null, null);
			localKeyStore.store(new FileOutputStream(localKeyStoreFile), localKeyStorePassword.toCharArray());
		} catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e) {
			e.printStackTrace();
		}
	}

	@SuppressWarnings("static-access")
	@Override
	public boolean saveKeypair(String keypair_name) {
		System.out.println("saveKeypair");
		try {
			/*
			 * System.out.println(access.getPublicKeyECCurve()); //prime192v1
			 * System.out.println(access.getPublicKeyAlgorithm()); //ec
			 * System.out.println(access.getIssuerSignatureAlgorithm());
			 * System.out.println(access.getPublicKeyParameter());
			 * System.out.println(access.getSubjectUniqueIdentifier());
			 * System.out.println(access.getEnabledAuthorityKeyID());
			 * 
			 * System.out.println(access.getGender());
			 * System.out.println(access.getPathLen());
			 * System.out.println(access.getSubjectDirectoryAttribute(0));
			 * System.out.println(access.getSubjectDirectoryAttribute(1));
			 * System.out.println(access.getDateOfBirth());
			 * System.out.println(access.isCritical(0));
			 * 
			 * System.out.println(access.isCritical(7));
			 * System.out.println(access.isCritical(8));
			 * 
			 * //access.setPublicKeyAlgorithm("RSA");
			 */
			if (access.getPublicKeyAlgorithm().equals("RSA")) {
				Integer parameter = Integer.valueOf(access.getPublicKeyParameter());
				RSAKeyGenParameterSpec rsaSpec = new RSAKeyGenParameterSpec(parameter, RSAKeyGenParameterSpec.F4);
				KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
				generator.initialize(rsaSpec, new SecureRandom());
				KeyPair keyPair = generator.generateKeyPair();

				X500Principal subject = new X500Principal(access.getSubject());

				X500Principal issuerName = new X500Principal(access.getSubject());

				BigInteger serial = new BigInteger(access.getSerialNumber().toString());

				X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerName, serial,
						access.getNotBefore(), access.getNotAfter(), subject, keyPair.getPublic());

				// =====================================EXTENSIONS==================================================

				// -----------------------------Basic Constraints--------------------------------------
				if (access.isCritical(Constants.BC) && access.isCA()) {
					builder.addExtension(Extension.basicConstraints, true,
							new BasicConstraints(Integer.parseInt(access.getPathLen())));
				}
				// ----------------------------Issuer Alternative Name--------------------------------
				String[] ext2par = super.access.getAlternativeName(Constants.IAN);
				if (ext2par.length != 0) {
					GeneralName[] ge = new GeneralName[ext2par.length];
					for (int i = 0; i < ext2par.length; i++) {
						String[] split = ext2par[i].split("=");

						int gn = GeneralName.otherName;
						if (split[0].equals("DNSName"))
							gn = GeneralName.dNSName;
						if (split[0].equals("RFC822Name"))
							gn = GeneralName.rfc822Name;
						if (split[0].equals("EDIPartyName"))
							gn = GeneralName.ediPartyName;
						if (split[0].equals("IPAddressName"))
							gn = GeneralName.iPAddress;
						if (split[0].equals("URIName"))
							gn = GeneralName.uniformResourceIdentifier;
						if (split[0].equals("x400Address"))
							gn = GeneralName.x400Address;
						if (split[0].equals("Directory"))
							gn = GeneralName.directoryName;
						if (gn == 0) {
							super.access.reportError("Uneli ste nekorektan oblik Issuer Alternative Names");
							return false;
						}
						ge[i] = new GeneralName(gn, ext2par[i]);
					}

					boolean ec2 = super.access.isCritical(Constants.IAN);

					builder.addExtension(Extension.issuerAlternativeName, ec2, new GeneralNames(ge));
				}
				// -----------------------------------Certificate_Policy---------------------------------------
				boolean ec3 = super.access.isCritical(Constants.CP);
				PolicyQualifierInfo pqInfo = new PolicyQualifierInfo(super.access.getCpsUri());
				PolicyInformation policyInfo = new PolicyInformation(PolicyQualifierId.id_qt_cps,
						new DERSequence(pqInfo));
				CertificatePolicies policies = new CertificatePolicies(policyInfo);
				builder.addExtension(Extension.certificatePolicies, ec3, policies);
				// ============================================================================================
				
				JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(
						access.getPublicKeyDigestAlgorithm());

				ContentSigner signer = contentSignerBuilder.build(keyPair.getPrivate());

				X509CertificateHolder holder = builder.build(signer);

				X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC")
						.getCertificate(holder);

				Certificate[] chain = new Certificate[1];
				chain[0] = certificate;

				localKeyStore.setKeyEntry(keypair_name, keyPair.getPrivate(), entyPassword.toCharArray(), chain);

				localKeyStore.store(new FileOutputStream(localKeyStoreFile), localKeyStorePassword.toCharArray());

				return true;
			}
			access.reportError("Pogresan Algoritam!");
			return false;
		} catch (CertificateException | KeyStoreException | NoSuchAlgorithmException | IOException
				| InvalidAlgorithmParameterException | NoSuchProviderException | IllegalStateException |

				OperatorCreationException e) {
			e.printStackTrace();
			return false;
		}

	}

	@Override
	public boolean signCSR(String file, String signer, String algorithm) {
		try {
			ContentSigner contentSigner = new JcaContentSignerBuilder(algorithm)
					.build((PrivateKey) localKeyStore.getKey(signer, entyPassword.toCharArray()));
			X500Name issuerName = new JcaX509CertificateHolder((X509Certificate) localKeyStore.getCertificate(signer))
					.getSubject();
			String alias = find(csr.getSubject());
			if (alias == null)
				return false;
			PrivateKey privateKey = (PrivateKey) localKeyStore.getKey(alias, localKeyStorePassword.toCharArray());
			X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuerName,
					new BigInteger(super.access.getSerialNumber(), 10), super.access.getNotBefore(),
					super.access.getNotAfter(), csr.getSubject(), csr.getSubjectPublicKeyInfo());

			// =====================================EXTENSIONS==================================================

			// -----------------------------Basic Constraints--------------------------------------
			if (access.isCritical(Constants.BC) && access.isCA()) {
				certBuilder.addExtension(Extension.basicConstraints, true,
						new BasicConstraints(Integer.parseInt(access.getPathLen())));
			}
			// ----------------------------Issuer Alternative Name--------------------------------
			String[] ext2par = super.access.getAlternativeName(Constants.IAN);
			if (ext2par.length != 0) {
				GeneralName[] ge = new GeneralName[ext2par.length];
				for (int i = 0; i < ext2par.length; i++) {
					String[] split = ext2par[i].split("=");

					int gn = GeneralName.otherName;
					if (split[0].equals("DNSName"))
						gn = GeneralName.dNSName;
					if (split[0].equals("RFC822Name"))
						gn = GeneralName.rfc822Name;
					if (split[0].equals("EDIPartyName"))
						gn = GeneralName.ediPartyName;
					if (split[0].equals("IPAddressName"))
						gn = GeneralName.iPAddress;
					if (split[0].equals("URIName"))
						gn = GeneralName.uniformResourceIdentifier;
					if (split[0].equals("x400Address"))
						gn = GeneralName.x400Address;
					if (split[0].equals("Directory"))
						gn = GeneralName.directoryName;
					if (gn == 0) {
						super.access.reportError("Uneli ste nekorektan oblik Issuer Alternative Names");
						return false;
					}
					ge[i] = new GeneralName(gn, ext2par[i]);
				}

				boolean ec2 = super.access.isCritical(Constants.IAN);

				certBuilder.addExtension(Extension.issuerAlternativeName, ec2, new GeneralNames(ge));
			}
			// -----------------------------------Certificate_Policy---------------------------------------
			boolean ec3 = super.access.isCritical(Constants.CP);
			PolicyQualifierInfo pqInfo = new PolicyQualifierInfo(super.access.getCpsUri());
			PolicyInformation policyInfo = new PolicyInformation(PolicyQualifierId.id_qt_cps,
					new DERSequence(pqInfo));
			CertificatePolicies policies = new CertificatePolicies(policyInfo);
			certBuilder.addExtension(Extension.certificatePolicies, ec3, policies);
			// ============================================================================================
			X509CertificateHolder certHolder = certBuilder.build(contentSigner);
			X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);
			Certificate[] certs = localKeyStore.getCertificateChain(signer);
			List<Certificate> newCerts = new ArrayList<Certificate>(certs.length + 1);
			if (((X509Certificate) localKeyStore.getCertificate(signer)).getBasicConstraints() < certs.length + 1)
				return false;
			newCerts.add(0, cert);
			for (int i = 0; i < certs.length; i++) {
				newCerts.add(certs[i]);
			}
			// localKeyStore.setKeyEntry(alias, privateKey,
			// localKeyStorePassword.toCharArray(), newCerts);
			// localKeyStore.store(new FileOutputStream(localKeyStoreFile),
			// localKeyStorePassword.toCharArray());
			// InputStream inStream = new FileInputStream(file);
			// BufferedInputStream bis = new BufferedInputStream(inStream);

			Store<Certificate> certs_stored = new JcaCertStore(newCerts);

			CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
			gen.addCertificates(certs_stored);
			// CMSProcessableInputStream msg = new CMSProcessableInputStream( new
			// ByteArrayInputStream( "signedhash".getBytes() ) );
			CMSSignedData sigData = gen.generate(new CMSProcessableByteArray(privateKey.getEncoded()), false);

			FileOutputStream os = new FileOutputStream(file);
			ASN1InputStream asn1 = new ASN1InputStream(sigData.getEncoded());
			DEROutputStream dos = new DEROutputStream(os);
			dos.writeObject(asn1.readObject());
			dos.close();
			os.close();
			return true;
		} catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException
				| OperatorCreationException | UnrecoverableKeyException | CMSException e) {
			e.printStackTrace();
			return false;
		}
	}

	public Certificate find() {
		Certificate certificateToExport = null;
		try {
			Enumeration<String> aliases = localKeyStore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				X509Certificate certificate = (X509Certificate) localKeyStore.getCertificate(alias);
				if (certificate.getSerialNumber().toString().compareTo(access.getSerialNumber()) == 0) {
					certificateToExport = certificate;
					break;
				}
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return null;
		}
		return certificateToExport;
	}

	public String find(X500Name subject_csr) {
		String certificateToExport = null;
		try {
			Enumeration<String> aliases = localKeyStore.aliases();
			String su1 = null;
			String su2 = null;
			for (RDN rdn : subject_csr.getRDNs()) {
				AttributeTypeAndValue first = rdn.getFirst();
				if (first.getType().equals(BCStyle.CN)) {
					su1 = first.getValue().toString();
				}
			}
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				X500Name subject = new JcaX509CertificateHolder((X509Certificate) localKeyStore.getCertificate(alias))
						.getSubject();
				for (RDN rdn : subject.getRDNs()) {
					AttributeTypeAndValue first = rdn.getFirst();
					if (first.getType().equals(BCStyle.CN)) {
						su2 = first.getValue().toString();
						break;
					}
				}
				if (su1.compareTo(su2) == 0) {
					certificateToExport = alias;
					break;
				}
			}
		} catch (KeyStoreException | CertificateEncodingException e) {
			e.printStackTrace();
			return null;
		}
		return certificateToExport;
	}

	public Certificate[] find_chain() {
		try {
			Enumeration<String> aliases = localKeyStore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				X509Certificate certificate = (X509Certificate) localKeyStore.getCertificate(alias);
				if (certificate.getSerialNumber().toString().compareTo(access.getSerialNumber()) == 0) {
					return localKeyStore.getCertificateChain(alias);
				}
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return null;
		}
		return null;
	}

}
