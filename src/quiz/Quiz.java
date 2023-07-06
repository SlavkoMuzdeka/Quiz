package quiz;

import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import gui.Login;

public class Quiz implements ActionListener {

	private JFrame frame;
	private JRadioButton[] buttons;
	private JButton btn1, btn2, btn3;;
	private ButtonGroup bg;
	private JLabel label;
	private JTextField text;

	private String[][] questions;
	private int count = 0;
	private int[] numberArray;
	private int buttonPressed = 0;
	private HashMap<Integer, String> map;
	private String answer;

	private int var = 30;
	private final String results = ".\\results\\results.txt";
	private final String password = ".\\password\\password.txt";
	private final byte[] saltByte = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
	private final byte[] iv = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
	
	public static final String publicCA1 = ".\\certificates\\keys\\publicCA1_4096.txt";
	public static final String privateCA1 = ".\\certificates\\keys\\privateCA1_4096.txt";

	public Quiz(String[][] questions) {
		createQuizForm(questions);
		generateRandomNumbers();
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		if (e.getSource() == btn1) {
			if (checkAnswers(buttonPressed - 1)) {
				count++;
			}
			if (buttonPressed < 5) {
				setQuestions();
				buttonPressed++;
			} else {
				writeResult();
				btn1.setVisible(false);
				btn2.setVisible(true);
				btn3.setVisible(true);
				JOptionPane.showInternalMessageDialog(null, "Number of correct answers " + count, "Quiz result",
						JOptionPane.INFORMATION_MESSAGE);
			}
		} else if (e.getSource() == btn2) {
			System.exit(0);
		} else if (e.getSource() == btn3) {
			showResults();
		}
	}

	private void createQuizForm(String[][] questions) {
		this.questions = questions;
		map = new HashMap<>();

		frame = new JFrame("Kviz");
		frame.setSize(700, 500);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.setResizable(false);
		frame.setLayout(null);
		frame.setLocation(400, 200);

		label = new JLabel();
		label.setBounds(80, 70, 650, 20);
		label.setFont(new Font("Verdana", Font.PLAIN, 15));
		frame.add(label);

		bg = new ButtonGroup();

		btn1 = new JButton("Sledece pitanje");
		btn1.addActionListener(this);
		btn1.setFocusable(false);
		frame.add(btn1);

		btn2 = new JButton("Kraj");
		btn2.setVisible(false);
		btn2.addActionListener(this);
		btn2.setFocusable(false);
		frame.add(btn2);

		btn3 = new JButton("Pregled rezultata");
		btn3.setVisible(false);
		btn3.addActionListener(this);
		btn3.setFocusable(false);
		frame.add(btn3);

		text = new JTextField();
		text.setBounds(100, 200, 450, 30);
		text.setVisible(false);
		frame.add(text);

		buttons = new JRadioButton[5];
		for (int i = 0; i < buttons.length; i++) {
			buttons[i] = new JRadioButton();
			buttons[i].setFocusable(false);
			bg.add(buttons[i]);
			frame.add(buttons[i]);
		}

		buttons[0].setBounds(100, 150, 450, 30);
		buttons[1].setBounds(100, 180, 450, 30);
		buttons[2].setBounds(100, 210, 450, 30);
		buttons[3].setBounds(100, 240, 450, 30);
		btn1.setBounds(150, 350, 150, 30);
		btn2.setBounds(450, 350, 150, 30);
		btn3.setBounds(150, 350, 150, 30);
	}

	private void generateRandomNumbers() {
		Random rand = new Random();
		numberArray = new int[5];
		for (int i = 0; i < numberArray.length; i++) {
			numberArray[i] = rand.nextInt(20);
		}
		setQuestions();
		buttonPressed++;
	}

	private void setQuestions() {
		int value = numberArray[buttonPressed];
		var = value;
		if (value == 2) {
			setButtonsAndLabel(2);
		} else if (value == 1) {
			setButtonsAndLabel(1);
		} else if (value == 0) {
			writeAnswer(0);
		} else if (value == 3) {
			setButtonsAndLabel(3);
		} else if (value == 4) {
			setButtonsAndLabel(4);
		} else if (value == 5) {
			writeAnswer(5);
		} else if (value == 6) {
			writeAnswer(6);
		} else if (value == 7) {
			setButtonsAndLabel(7);
		} else if (value == 8) {
			setButtonsAndLabel(8);
		} else if (value == 9) {
			setButtonsAndLabel(9);
		} else if (value == 10) {
			setButtonsAndLabel(10);
		} else if (value == 11) {
			setButtonsAndLabel(11);
		} else if (value == 12) {
			setButtonsAndLabel(12);
		} else if (value == 13) {
			writeAnswer(13);
		} else if (value == 14) {
			setButtonsAndLabel(14);
		} else if (value == 15) {
			setButtonsAndLabel(15);
		} else if (value == 16) {
			setButtonsAndLabel(16);
		} else if (value == 17) {
			setButtonsAndLabel(17);
		} else if (value == 18) {
			setButtonsAndLabel(18);
		} else if (value == 19) {
			writeAnswer(19);
		}
	}

	private void setButtonsAndLabel(int i) {
		label.setText(questions[i][0]);
		buttons[0].setText(questions[i][1]);
		buttons[1].setText(questions[i][2]);
		buttons[2].setText(questions[i][3]);
		buttons[3].setText(questions[i][4]);
		for (int j = 0; j < buttons.length; j++) {
			buttons[j].setVisible(true);
			buttons[j].setSelected(true);
		}
		text.setVisible(false);
		text.setText("");
	}

	private void writeAnswer(int i) {
		label.setText(questions[i][0]);
		for (int j = 0; j < buttons.length; j++) {
			buttons[j].setVisible(false);
		}
		text.setVisible(true);
		text.setText("");
	}

	private boolean checkAnswers(int value) {
		if (var == 30 || value == -1) {
			return false;
		}
		int numberOfQuestion = numberArray[value];
		if (numberOfQuestion == 2) {
			return (buttons[3].isSelected());
		} else if (numberOfQuestion == 1) {
			return (buttons[2].isSelected());
		} else if (numberOfQuestion == 0) {
			getAnswer(0);
			if (map.get(0).toUpperCase().equals("EKVATOR")) {
				return true;
			}
		} else if (numberOfQuestion == 3) {
			return (buttons[0].isSelected());
		} else if (numberOfQuestion == 4) {
			return (buttons[0].isSelected());
		} else if (numberOfQuestion == 5) {
			getAnswer(5);
			if (map.get(5).toUpperCase().equals("INSEKAT")) {
				return true;
			}
		} else if (numberOfQuestion == 6) {
			getAnswer(6);
			if (map.get(6).toUpperCase().equals("RUSIJA")) {
				return true;
			}
		} else if (numberOfQuestion == 7) {
			return (buttons[2].isSelected());
		} else if (numberOfQuestion == 8) {
			return (buttons[0].isSelected());
		} else if (numberOfQuestion == 9) {
			return (buttons[2].isSelected());
		} else if (numberOfQuestion == 10) {
			return (buttons[1].isSelected());
		} else if (numberOfQuestion == 11) {
			return (buttons[0].isSelected());
		} else if (numberOfQuestion == 12) {
			return (buttons[0].isSelected());
		} else if (numberOfQuestion == 13) {
			getAnswer(13);
			if (map.get(13).toUpperCase().equals("V")) {
				return true;
			}
		} else if (numberOfQuestion == 14) {
			return (buttons[1].isSelected());
		} else if (numberOfQuestion == 15) {
			return (buttons[3].isSelected());
		} else if (numberOfQuestion == 16) {
			return (buttons[1].isSelected());
		} else if (numberOfQuestion == 17) {
			return (buttons[2].isSelected());
		} else if (numberOfQuestion == 18) {
			return (buttons[1].isSelected());
		} else if (numberOfQuestion == 19) {
			getAnswer(19);
			if (map.get(19).toUpperCase().equals("ANTARKTIK")) {
				return true;
			}
		}
		return false;
	}

	public void writeResult() {
		// writeSymmetricKey();
		String password = readSymmetricKey();
		try {
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec spec = new PBEKeySpec(password.toCharArray(), saltByte, 10000, 128);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKeySpec skey = new SecretKeySpec(tmp.getEncoded(), "AES");
			IvParameterSpec ivspec = new IvParameterSpec(iv);
			Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
			ci.init(Cipher.ENCRYPT_MODE, skey, ivspec);

			Date dNow = new Date();
			SimpleDateFormat ft = new SimpleDateFormat("hh:mm:ss");
			String result = String.valueOf(count);
			String information = Login.userName.toString() + "\t" + "\t" + ft.format(dNow) + "\t" + "\t" + result;
			byte[] string = ci.doFinal(information.getBytes());
			String enc = Base64.getEncoder().encodeToString(string);
			BufferedWriter bw1 = new BufferedWriter(new FileWriter(results, true));
			bw1.write(enc + "\n");
			bw1.close();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	// This method has to be called only once, if there aren't any symmetric key
	/*
	 * private void writeSymmetricKey() { File filePublicKey = new File(publicCA1);
	 * try (FileInputStream fis = new FileInputStream(publicCA1)) { byte[]
	 * encodedPublicKey = new byte[(int) filePublicKey.length()];
	 * fis.read(encodedPublicKey); fis.close(); KeyFactory keyFactory1 =
	 * KeyFactory.getInstance("RSA"); X509EncodedKeySpec publicKeySpec = new
	 * X509EncodedKeySpec(encodedPublicKey); PublicKey publicKey =
	 * keyFactory1.generatePublic(publicKeySpec); Cipher cipher1 =
	 * Cipher.getInstance("RSA/ECB/PKCS1Padding"); cipher1.init(Cipher.ENCRYPT_MODE,
	 * publicKey); byte[] encryptedBytes = cipher1.doFinal("sigurnost".getBytes());
	 * String enc = Base64.getEncoder().encodeToString(encryptedBytes);
	 * BufferedWriter bw = new BufferedWriter(new FileWriter(password));
	 * bw.write(enc + "\n"); bw.close(); } catch (Exception ex) {
	 * ex.printStackTrace(); } }
	 */

	private String readSymmetricKey() {
		File filePrivateKey = new File(privateCA1);
		try (FileInputStream fis = new FileInputStream(privateCA1)) {
			byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
			fis.read(encodedPrivateKey);
			fis.close();
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
			PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
			BufferedReader br = new BufferedReader(new FileReader(password));
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

	private void showResults() {
		try (BufferedReader bf1 = new BufferedReader(new FileReader(results))) {
			String s;

			JFrame frame1 = new JFrame("Quiz results");
			frame1.setSize(400, 300);
			frame1.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
			frame1.setLocation(500, 250);

			JPanel panel = new JPanel(new GridLayout());
			JTextArea area = new JTextArea();
			String password = readSymmetricKey();
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec spec = new PBEKeySpec(password.toCharArray(), saltByte, 10000, 128);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKeySpec skey = new SecretKeySpec(tmp.getEncoded(), "AES");
			Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
			ci.init(Cipher.DECRYPT_MODE, skey, new IvParameterSpec(iv));

			while ((s = bf1.readLine()) != null) {
				byte[] decrypt = Base64.getDecoder().decode(s);
				byte[] string = ci.doFinal(decrypt);
				area.append(new String(string) + "\n");
			}
			panel.add(area);
			JScrollPane pane = new JScrollPane(panel);
			frame1.add(pane);
			frame1.setVisible(true);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	private void getAnswer(int i) {
		answer = text.getText();
		map.put(i, answer);
	}

	public JFrame getFrame() {
		return frame;
	}
}
