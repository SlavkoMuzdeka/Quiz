package gui;

import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;
import java.util.Date;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

public class Registration implements ActionListener {

	private final String hashedPasswords = ".\\passwords\\hashedPasswords.txt";
	private final String requests = ".\\certificates\\requests";
	private final String numberOfRequests = ".\\certificates\\serialNumber.txt";
	
	private final String privateCA1 = ".\\certificates\\keys\\privateCA1_4096.txt";
	private final String privateCA2 = ".\\certificates\\keys\\privateCA2_4096.txt";
	private final String certificateCA1 = ".\\certificates\\CA1.crt";
	private final String certificateCA2 = ".\\certificates\\CA2.crt";
	private final String issuedCertificates = ".\\certificates\\issuedCertificates.txt";

	private final String cert = "C:\\Users\\slavko\\Desktop";

	private final byte[] byteSalt = { 1, 2, 3, 4, 5, 6, 7, 8 };
	private final byte[] iv = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

	private JFrame frame;
	private JLabel label1, label2, label3, label4, label5, label6, label7, label8;
	private JTextField text1, text2, text5, text6, text7;
	private JPasswordField text3, text4;
	private JButton btn1, btn2;

	public Registration() {
		createFormForRegistration();
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		if (e.getSource() == btn1) {
			if (text1.getText().isEmpty() || text2.getText().isEmpty() || text3.getPassword().toString().equals("")
					|| text4.getPassword().toString().equals("") || text5.getText().isEmpty()
					|| text6.getText().isEmpty() || text7.getText().isEmpty()) {
				JOptionPane.showInternalMessageDialog(null, "You must enter all values", "Try again",
						JOptionPane.ERROR_MESSAGE);
			} else if (!String.valueOf(text3.getPassword()).equals(String.valueOf(text4.getPassword()))) {
				JOptionPane.showInternalMessageDialog(null, "Passwords must me the same", "Try again",
						JOptionPane.ERROR_MESSAGE);
			} else {
				try {
					if (!usernameExists()) {
						if (makeCertificateRequest()) {
							JOptionPane.showInternalMessageDialog(null, "You have been sucessfully registered",
									"Sucessfull registration", JOptionPane.INFORMATION_MESSAGE);
							frame.setVisible(false);
							hashPassword();
						}
					} else {
						JOptionPane.showInternalMessageDialog(null, "Username must be unique.", "Try again",
								JOptionPane.ERROR_MESSAGE);
					}
				} catch(Exception ex) {
					ex.printStackTrace();
				}
			}
		} else if (e.getSource() == btn2) {
			text1.setText("");
			text2.setText("");
			text3.setText("");
			text4.setText("");
			text5.setText("");
			text6.setText("");
			text7.setText("");
		}
	}

	private boolean usernameExists() {
		try (BufferedReader bf = new BufferedReader(new FileReader(hashedPasswords))) {
			String s;
			String[] niz;
			while ((s = bf.readLine()) != null) {
				niz = s.split(";");
				if (niz[0].equals(text2.getText())) {
					return true;
				}
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return false;
	}

	private boolean makeCertificateRequest() throws Exception {
		String country = text6.getText();
		String city = text7.getText();
		String name = text1.getText();
		String username = text2.getText();
		String email = text5.getText();

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
				new X500Principal("emailAddress = " + email + ", CN = " + name + ", O = " + username + ", L = " + city
						+ ", C = " + country),
				keyPair.getPublic());
		JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
		ContentSigner signer = csBuilder.build(keyPair.getPrivate());
		PKCS10CertificationRequest csr = p10Builder.build(signer);

		BufferedReader bf = new BufferedReader(new FileReader(numberOfRequests));
		String br = bf.readLine();
		JcaPEMWriter jcaPEMWriter = new JcaPEMWriter(new FileWriter(requests + "/" + username + ".csr"));
		jcaPEMWriter.writeObject(csr);
		jcaPEMWriter.close();

		File filePrivateKey;
		FileInputStream fis;
		Integer i = Integer.parseInt(br);
		if (i % 2 == 0) {
			filePrivateKey = new File(privateCA1);
			fis = new FileInputStream(privateCA1);
		} else {
			filePrivateKey = new File(privateCA2);
			fis = new FileInputStream(privateCA2);
		}

		byte[] keyBytes = new byte[(int) filePrivateKey.length()];
		fis.read(keyBytes);
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
		signCertificate(csr, keyPair, privateKey, i, username);
		fis.close();
		bf.close();
		return true;
	}

	private void signCertificate(PKCS10CertificationRequest csr, KeyPair pair, PrivateKey caPrivate, Integer i,
			String userName) throws Exception {
		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		AsymmetricKeyParameter foo = PrivateKeyFactory.createKey(caPrivate.getEncoded());
		SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());
		
		FileInputStream fis = null;
		BufferedInputStream bis = null;
		X509Certificate certificate = null;
		String str = "";
		if (i % 2 == 0) {
			fis = new FileInputStream(new File(certificateCA2));
			bis = new BufferedInputStream(fis);
			certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(bis);
			str = certificate.getSubjectX500Principal().toString();
		} else {
			fis = new FileInputStream(new File(certificateCA1));
			bis = new BufferedInputStream(fis);
			certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(bis);
			str = certificate.getSubjectX500Principal().toString();
		}
		
		X509v3CertificateBuilder myCertificateGenerator = new X509v3CertificateBuilder(new X500Name(str),
				new BigInteger(String.valueOf(i)), new Date(System.currentTimeMillis()),
				new Date(System.currentTimeMillis() + 30 * 365 * 24 * 60 * 60 * 1000), csr.getSubject(), keyInfo);
		myCertificateGenerator.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
		KeyUsage usage = new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature | KeyUsage.nonRepudiation
				| KeyUsage.dataEncipherment);
		myCertificateGenerator.addExtension(Extension.keyUsage, false, usage);
		ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(foo);
		X509CertificateHolder holder = myCertificateGenerator.build(sigGen);
		Certificate eeX509CertificateStructure = holder.toASN1Structure();
		CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
		InputStream is1 = new ByteArrayInputStream(eeX509CertificateStructure.getEncoded());
		X509Certificate theCert = (X509Certificate) cf.generateCertificate(is1);
		is1.close();
		
		BufferedReader bf = new BufferedReader(new FileReader(numberOfRequests));
		String br = bf.readLine();
		File newDirectory = new File(cert + "/" + userName);
		boolean t = newDirectory.mkdir();
		if (t) {
			JcaPEMWriter jcaPEMWriter = new JcaPEMWriter(
					new FileWriter(newDirectory.getCanonicalPath() + "/" + userName + ".crt"));
			jcaPEMWriter.writeObject(theCert);
			jcaPEMWriter.close();
			PrivateKey privateKey = pair.getPrivate();
			encryptPrivateKey(privateKey, newDirectory, userName);
			JOptionPane.showInternalMessageDialog(null, "Sertifikat se nalazi u: " + newDirectory.getCanonicalPath(),
					"Sertifikat napravljen", JOptionPane.INFORMATION_MESSAGE);
		}
		Integer num = Integer.parseInt(br);
		BufferedWriter bf1 = new BufferedWriter(new FileWriter(numberOfRequests));
		Integer number = num + 1;
		bf1.write(number.toString());
		BufferedReader bf3 = new BufferedReader(new FileReader(issuedCertificates));
		StringBuilder fileContent = new StringBuilder();
		String str1;
		while ((str1 = bf3.readLine()) != null) {
			fileContent.append(str1 + "\n");
		}
		fileContent.append("0" + ";" + csr.getSubject() + "\n");
		BufferedWriter bf2 = new BufferedWriter(new FileWriter(issuedCertificates));
		bf2.write(fileContent.toString());
		bf.close();
		bf1.close();
		bf2.close();
		bf3.close();
	}
	
	private void encryptPrivateKey(PrivateKey privateKey,File newDirectory,String userName) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		String password = String.valueOf(text3.getPassword());
		byte[] plainText = privateKey.getEncoded();
		IvParameterSpec ivParamSpec = new IvParameterSpec(iv);
		PBEParameterSpec pbeParamSpec = new PBEParameterSpec(byteSalt, 10000, ivParamSpec);
		PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
        SecretKey secretKey = kf.generateSecret(keySpec);
        Cipher enc = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
        enc.init(Cipher.ENCRYPT_MODE, secretKey,pbeParamSpec);
        byte[] encrypted = enc.doFinal(plainText);
        String str = Base64.getEncoder().encodeToString(encrypted);
        BufferedWriter bw = new BufferedWriter(new FileWriter(newDirectory.getCanonicalFile()+"/privateKey.key"));
        bw.write(str+"\n");
        bw.close();
	}

	private void createFormForRegistration() {
		frame = new JFrame("REGISTRATION FORM");
		frame.setSize(600, 690);
		frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		frame.setResizable(false);
		frame.setLayout(null);
		frame.setLocation(500, 100);

		label1 = new JLabel("Registration");
		label1.setBounds(230, 20, 300, 50);
		label1.setFont(new Font("Verdana", Font.PLAIN, 23));

		frame.add(label1);
		label2 = new JLabel("Name and surname:");
		label2.setBounds(70, 110, 350, 30);
		label2.setFont(new Font("Verdana", Font.PLAIN, 15));
		frame.add(label2);

		text1 = new JTextField();
		text1.setBounds(300, 110, 230, 30);
		frame.add(text1);

		label3 = new JLabel("Username:");
		label3.setBounds(70, 170, 350, 30);
		label3.setFont(new Font("Verdana", Font.PLAIN, 15));
		frame.add(label3);

		text2 = new JTextField();
		text2.setBounds(300, 170, 230, 30);
		frame.add(text2);

		label4 = new JLabel("Password:");
		label4.setBounds(70, 230, 350, 30);
		label4.setFont(new Font("Verdana", Font.PLAIN, 15));
		frame.add(label4);

		text3 = new JPasswordField();
		text3.setBounds(300, 230, 230, 30);
		frame.add(text3);

		label5 = new JLabel("Password again:");
		label5.setBounds(70, 290, 350, 30);
		label5.setFont(new Font("Verdana", Font.PLAIN, 15));
		frame.add(label5);

		text4 = new JPasswordField();
		text4.setBounds(300, 290, 230, 30);
		frame.add(text4);

		label6 = new JLabel("E-mail:");
		label6.setBounds(70, 350, 350, 30);
		label6.setFont(new Font("Verdana", Font.PLAIN, 15));
		frame.add(label6);

		text5 = new JTextField();
		text5.setBounds(300, 350, 230, 30);
		frame.add(text5);

		label7 = new JLabel("Country:");
		label7.setBounds(70, 410, 350, 30);
		label7.setFont(new Font("Verdana", Font.PLAIN, 15));
		frame.add(label7);

		text6 = new JTextField();
		text6.setBounds(300, 410, 230, 30);
		frame.add(text6);

		label8 = new JLabel("City:");
		label8.setBounds(70, 470, 350, 30);
		label8.setFont(new Font("Verdana", Font.PLAIN, 15));
		frame.add(label8);

		text7 = new JTextField();
		text7.setBounds(300, 470, 230, 30);
		frame.add(text7);

		btn1 = new JButton("Registration");
		btn1.addActionListener(this);
		btn1.setFocusable(false);
		btn1.setBounds(140, 550, 120, 30);
		frame.add(btn1);

		btn2 = new JButton("Cancel");
		btn2.addActionListener(this);
		btn2.setFocusable(false);
		btn2.setBounds(350, 550, 120, 30);
		frame.add(btn2);
	}

	private void hashPassword() {
		try (BufferedWriter bf = new BufferedWriter(new FileWriter(hashedPasswords, true))) {
			byte[] salt = String.valueOf(text3.getPassword()).getBytes();
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(salt);
			byte[] hashedPassword = md.digest();

			StringBuilder sb = new StringBuilder();
			for (byte b : hashedPassword) {
				sb.append(String.format("%02x", b));
			}
			bf.write(text2.getText() + ";" + sb.toString() + "\n");
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	
	public JFrame getFrame() {
		return frame;
	}
	

	public void setFrame(JFrame frame) {
		this.frame = frame;
	}
	

	public JTextField getText1() {
		return text1;
	}
	

	public void setText1(JTextField text1) {
		this.text1 = text1;
	}
	

	public JTextField getText2() {
		return text2;
	}
	

	public void setText2(JTextField text2) {
		this.text2 = text2;
	}
	

	public JTextField getText5() {
		return text5;
	}
	

	public void setText5(JTextField text5) {
		this.text5 = text5;
	}
	

	public JTextField getText6() {
		return text6;
	}
	

	public void setText6(JTextField text6) {
		this.text6 = text6;
	}
	

	public JTextField getText7() {
		return text7;
	}
	

	public void setText7(JTextField text7) {
		this.text7 = text7;
	}
	

	public JPasswordField getText3() {
		return text3;
	}
	

	public void setText3(JPasswordField text3) {
		this.text3 = text3;
	}
	

	public JPasswordField getText4() {
		return text4;
	}
	

	public void setText4(JPasswordField text4) {
		this.text4 = text4;
	}

}
