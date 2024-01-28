import javax.swing.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class CryptoAES {
    private static SecretKey secretKey;
    private static Cipher cipher;
    private static final String AES = "AES";

    public static void main(String[] args) {
        // Initialize AES Cipher
        try {
            cipher = Cipher.getInstance(AES);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }

        // GUI setup
        JFrame frame = new JFrame("Crypto-AES");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 200);

        JTextField txtInput = new JTextField(20);
        JTextField txtOutput = new JTextField(20);
        txtOutput.setEditable(false);
        JButton btnEncrypt = new JButton("Encrypt");
        JButton btnDecrypt = new JButton("Decrypt");

        JPanel panel = new JPanel();
        panel.add(txtInput);
        panel.add(btnEncrypt);
        panel.add(btnDecrypt);
        panel.add(txtOutput);
        frame.getContentPane().add(BorderLayout.CENTER, panel);

        // Button Actions
        btnEncrypt.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String plainText = txtInput.getText();
                txtOutput.setText(encrypt(plainText));
            }
        });

        btnDecrypt.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String cipherText = txtOutput.getText();
                txtOutput.setText(decrypt(cipherText));
            }
        });

        frame.setVisible(true);
    }

    public static String encrypt(String strToEncrypt) {
        try {
            secretKey = generateKey();
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static String decrypt(String strToDecrypt) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    private static SecretKey generateKey() {
        // 128 bit hardcoded key. In practice, this should be securely stored or generated
        byte[] key = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
        return new SecretKeySpec(key, AES);
    }
}
