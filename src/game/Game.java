package game;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import gui.Login;
import gui.Registration;
import quiz.Quiz;
import stegenography.Stegenography;

public class Game {

	private static final String passwordPath = ".\\passwords\\password1.txt";

	public static void main(String[] args) {
		try {
			Quiz quiz;
			String[][] questions = new String[20][5];
			String[] line = new String[5];
			writeSymmetricKey();
			String password = readSymmetricKey();
			byte[] saltBytes = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), saltBytes, 65536, 128);
			SecretKey secretKey = factory.generateSecret(spec);
			SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");
			Cipher cipher = Cipher.getInstance("AES");
			Cipher cipher1 = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, secret);
			cipher1.init(Cipher.DECRYPT_MODE, secret);

			// This method is called only once, when application is started the first time,
			// then it needs to be commented (when there are no images which are encrypted using stegenography
			//doStegenograph(cipher);
			
			for (int i = 0; i < 20; i++) {
				String text = Stegenography.decode(new File("./images/cryptograph" + i + "_crypted.bmp"));
				byte[] decrypt = Base64.getDecoder().decode(text);
				byte[] string = cipher1.doFinal(decrypt);
				String str = new String(string);
				line = str.split(";");
				for (int j = 0; j < line.length; j++) {
					questions[i][j] = new String(line[j]);
				}
			}
			quiz = new Quiz(questions);
			Registration registration = new Registration();
			new Login(registration, quiz);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	public static void writeSymmetricKey() {
		File filePublicKey = new File(Quiz.publicCA1);
		try (FileInputStream fis = new FileInputStream(Quiz.publicCA1)) {
			byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
			fis.read(encodedPublicKey);
			KeyFactory keyFactory1 = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
			PublicKey publicKey = keyFactory1.generatePublic(publicKeySpec);
			Cipher cipher1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher1.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] encryptedBytes = cipher1.doFinal("sigurnostt".getBytes());
			String enc = Base64.getEncoder().encodeToString(encryptedBytes);
			BufferedWriter bw = new BufferedWriter(new FileWriter(passwordPath));
			bw.write(enc + "\n");
			bw.close();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	public static String readSymmetricKey() {
		File filePrivateKey = new File(Quiz.privateCA1);
		try (FileInputStream fis = new FileInputStream(filePrivateKey)) {
			byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
			fis.read(encodedPrivateKey);
			fis.close();
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
			PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
			BufferedReader br = new BufferedReader(new FileReader(passwordPath));
			String str = br.readLine();
			br.close();
			byte[] decrypt = Base64.getDecoder().decode(str);
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] decryptedBytes = cipher.doFinal(decrypt);
			String password = new String(decryptedBytes);
			return password;
		} catch (Exception ex) {
			ex.printStackTrace();
			return "";
		}
	}

	/*private static void doStegenograph(Cipher cipher) {
		try (BufferedReader bf = new BufferedReader(new FileReader(questions))) {
			String s;
			for (int i = 0; i < 20; i++) {
				s = bf.readLine();
				byte[] encrypted = cipher.doFinal(s.getBytes());
				String enc = Base64.getEncoder().encodeToString(encrypted);
				Stegenography.encode(new File("./images/cryptograph" + i + ".bmp"), enc);
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}*/
}
