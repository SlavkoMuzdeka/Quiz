package gui;

import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.font.TextAttribute;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import quiz.Quiz;

public class Login extends MouseAdapter implements ActionListener {

	private JFrame frame;
	private JLabel label1, label2, label3, label4;
	private JButton btn1, btn2;
	private JTextField text1;
	private JPasswordField text2;

	private Quiz quiz;
	private Registration registration;

	private final String crlCA1 = ".\\CA1crl.crl";
	private final String crlCA2 = ".\\CA2crl.crl";
	private final String crlList = ".\\crl";
	private final String hashedPasswords = ".\\passwords\\hashedPasswords.txt";
	private final String issuedCertificates = ".\\certificates\\issuedCertificates.txt";
	private final String privateCA1 = ".\\certificates\\keys\\privateCA1_4096.txt";
	private final String privateCA2 = ".\\certificates\\keys\\privateCA2_4096.txt";

	public static String certificatePath = "";
	public static String userName;

	public Login(Registration registration, Quiz quiz) {
		this.registration = registration;
		this.quiz = quiz;
		createForm();
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		if (e.getSource() == btn2) {
			text1.setText("");
			text2.setText("");
		} else if (e.getSource() == btn1) {
			if (text1.getText().isEmpty()) {
				JOptionPane.showInternalMessageDialog(null, "You must enter a value", "Try again",
						JOptionPane.ERROR_MESSAGE);
			} else {
				certificatePath = JOptionPane.showInputDialog("Enter a path(absolute) to the certificate");
				if ("".equals(certificatePath) || certificatePath == null
						|| certificatePath.endsWith(".crt") == false) {
					JOptionPane.showInternalMessageDialog(null, "Enter a path(absolute) to the certificate",
							"Try again", JOptionPane.ERROR_MESSAGE);
				} else {
					File file = new File(certificatePath);
					if (file.isFile()) {
						try {
							if (login() == true) {
								String str = text1.getText();
								userName = str;
								if (!certificateValidity()) {
									havePlayed();
									frame.setVisible(false);
									quiz.getFrame().setVisible(true);
								} else {
									JOptionPane.showInternalMessageDialog(null, "Certificate is invalid",
											"Register first", JOptionPane.ERROR_MESSAGE);
								}
							} else {
								JOptionPane.showInternalMessageDialog(null, "Incorrect username and/or password",
										"Try again", JOptionPane.ERROR_MESSAGE);
							}
						} catch (Exception ex) {
							ex.printStackTrace();
						}
					} else {
						JOptionPane.showInternalMessageDialog(null, "Wrong path", "Try again",
								JOptionPane.ERROR_MESSAGE);
					}
				}
			}
		}
	}

	private void createForm() {
		frame = new JFrame("Login");
		frame.setSize(400, 400);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.setResizable(false);
		frame.setLayout(null);
		frame.setLocation(550, 200);

		label1 = new JLabel("Username:");
		label1.setBounds(70, 110, 350, 30);
		label1.setFont(new Font("Verdana", Font.PLAIN, 13));
		frame.add(label1);

		label2 = new JLabel("Password:");
		label2.setBounds(70, 180, 350, 20);
		label2.setFont(new Font("Verdana", Font.PLAIN, 13));
		frame.add(label2);

		text1 = new JTextField();
		text1.setBounds(160, 110, 200, 30);
		frame.add(text1);

		text2 = new JPasswordField();
		text2.setBounds(160, 180, 200, 30);
		frame.add(text2);

		btn1 = new JButton("Login");
		btn1.addActionListener(this);
		btn1.setFocusable(false);
		btn1.setBounds(90, 250, 80, 30);
		frame.add(btn1);

		btn2 = new JButton("Reset");
		btn2.addActionListener(this);
		btn2.setFocusable(false);
		btn2.setBounds(230, 250, 80, 30);
		frame.add(btn2);

		label3 = new JLabel("Login");
		label3.setBounds(170, 20, 300, 50);
		label3.setFont(new Font("Verdana", Font.PLAIN, 19));
		frame.add(label3);

		label4 = new JLabel("Click here for registration.");
		Font font = label4.getFont();
		Map<TextAttribute, Object> attributes = new HashMap<>(font.getAttributes());
		attributes.put(TextAttribute.UNDERLINE, TextAttribute.UNDERLINE_ON);
		label4.setFont(font.deriveFont(attributes));
		label4.setBounds(120, 300, 300, 30);
		label4.addMouseListener(this);
		frame.add(label4);

		frame.setVisible(true);
	}

	private boolean login() throws Exception {
		String userName = text1.getText();
		String password = String.valueOf(text2.getPassword());

		BufferedReader bf = new BufferedReader(new FileReader(hashedPasswords));
		String s, pomPassword = "";
		String[] niz = new String[2];
		while ((s = bf.readLine()) != null) {
			niz = s.split(";");
			if (niz[0].equals(userName)) {
				pomPassword = niz[1];
			}
		}
		bf.close();

		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] salt = password.getBytes();
		md.update(salt);

		byte[] hashedPassword = md.digest();
		StringBuilder sb = new StringBuilder();
		for (byte b : hashedPassword)
			sb.append(String.format("%02x", b));

		if (pomPassword.equals(sb.toString())) {
			return true;
		}
		return false;
	}

	private boolean certificateValidity() throws Exception {
		FileInputStream fis = new FileInputStream(new File(certificatePath));
		BufferedInputStream bis = new BufferedInputStream(fis);
		X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
				.generateCertificate(bis);

		String certIssuerDN = certificate.getIssuerX500Principal().toString();
		String certIssuerName = certIssuerDN.substring(37, 40);
		FileInputStream fis1 = null;
		CertificateFactory cf = null;
		X509CRL crl = null;

		if ("CA1".equals(certIssuerName)) {
			fis1 = new FileInputStream(crlCA1);
			cf = CertificateFactory.getInstance("X.509");
			crl = (X509CRL) cf.generateCRL(fis1);
		} else {
			fis1 = new FileInputStream(crlCA2);
			cf = CertificateFactory.getInstance("X.509");
			crl = (X509CRL) cf.generateCRL(fis1);
		}
		Date today = new Date();
		if (today.after(certificate.getNotAfter())
				|| crl.getRevokedCertificate(certificate.getSerialNumber()) != null) {
			return true;
		}
		String str = certificate.getSubjectX500Principal().toString();
		if (!str.subSequence(str.indexOf("O=", 0) + 2, str.indexOf("O=", 0) + userName.length() + 2).equals(userName)) {
			return true;
		}
		return false;
	}

	private void havePlayed() throws Exception {
		String s;
		String[] niz = new String[2];
		Integer i, number = 0;
		StringBuilder fileContent = new StringBuilder();
		BufferedReader bf = new BufferedReader(new FileReader(issuedCertificates));
		while ((s = bf.readLine()) != null) {
			niz = s.split(";");
			if (niz[1].contains(text1.getText())) {
				i = Integer.parseInt(niz[0]);
				number = i + 1;
				if (number >= 3) {
					revokeCertificate();
				}
				niz[0] = number.toString();
				fileContent.append(niz[0] + ";" + niz[1] + "\n");
			} else {
				fileContent.append(niz[0] + ";" + niz[1] + "\n");
			}
		}
		bf.close();
		BufferedWriter bf1 = new BufferedWriter(new FileWriter(issuedCertificates));
		bf1.write(fileContent.toString());
		bf1.close();
	}

	private void revokeCertificate() throws Exception {
		FileInputStream fis1 = new FileInputStream(new File(certificatePath));
		BufferedInputStream bis = new BufferedInputStream(fis1);
		X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(bis);
		String certIssuerDN = cert.getIssuerX500Principal().toString();
		String certIssuerName = certIssuerDN.substring(37, 40);
		
		PrivateKey privateKey = null;
		File filePrivateKey = null;
		FileInputStream fis = null;
		CertificateFactory cf = null;
		X509CRL crl = null;
		
		if ("CA1".equals(certIssuerName)) {
			fis = new FileInputStream(crlCA1);
			cf = CertificateFactory.getInstance("X.509");
			crl = (X509CRL) cf.generateCRL(fis);
			filePrivateKey = new File(privateCA1);
			fis = new FileInputStream(privateCA1);
		} else {
			fis = new FileInputStream(crlCA2);
			cf = CertificateFactory.getInstance("X.509");
			crl = (X509CRL) cf.generateCRL(fis);
			filePrivateKey = new File(privateCA2);
			fis = new FileInputStream(privateCA2);
		}
		byte[] keyBytes = new byte[(int) filePrivateKey.length()];
		fis.read(keyBytes);
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		privateKey = keyFactory.generatePrivate(privateKeySpec);
		fis.close();
		
		X509CRLHolder crlHolder = new X509CRLHolder(crl.getEncoded());
		X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(crlHolder);
		crlBuilder.addCRLEntry(cert.getSerialNumber(), new Date(), 5);
		JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(crl.getSigAlgName());
		ContentSigner signer = csBuilder.build(privateKey);
		X509CRLHolder crlHolder1 = crlBuilder.build(signer);
		FileOutputStream fos = null;
		if ("CA1".equals(certIssuerName)) {
			crl = new JcaX509CRLConverter().getCRL(crlHolder1);
			fos = new FileOutputStream(crlList + "/CA1crl.crl");
			fos.write(crl.getEncoded());
		} else {
			crl = new JcaX509CRLConverter().getCRL(crlHolder1);
			fos = new FileOutputStream(crlList + "/CA2crl.crl");
			fos.write(crl.getEncoded());
		}
		fos.close();
	}
	
	@Override
	public void mouseClicked(MouseEvent e) {
		this.registration.getText1().setText("");
		this.registration.getText2().setText("");
		this.registration.getText3().setText("");
		this.registration.getText4().setText("");
		this.registration.getText5().setText("");
		this.registration.getText6().setText("");
		this.registration.getText7().setText("");
		this.registration.getFrame().setVisible(true);
	}
}
