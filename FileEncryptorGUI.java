import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.*;
import java.io.*;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;

public class FileEncryptorGUI extends JFrame {

    private JTextField keyField;
    private JTextField fileField;
    private JComboBox<String> algorithmBox;
    private JButton encryptButton, decryptButton, browseButton;

    public FileEncryptorGUI() {
        setTitle("Secure File Encryptor");
        setSize(500, 250);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        JPanel inputPanel = new JPanel(new GridLayout(4, 2, 10, 10));

        inputPanel.add(new JLabel("Encryption Key:"));
        keyField = new JPasswordField();
        inputPanel.add(keyField);

        inputPanel.add(new JLabel("File Path:"));
        fileField = new JTextField();
        fileField.setTransferHandler(new FileDropHandler());
        inputPanel.add(fileField);

        inputPanel.add(new JLabel("Algorithm:"));
        algorithmBox = new JComboBox<>(new String[]{"XOR", "AES"});
        inputPanel.add(algorithmBox);

        browseButton = new JButton("Browse File");
        browseButton.addActionListener(e -> chooseFile());
        inputPanel.add(browseButton);

        JPanel buttonPanel = new JPanel();
        encryptButton = new JButton("Encrypt");
        decryptButton = new JButton("Decrypt");
        encryptButton.addActionListener(e -> processFile(true));
        decryptButton.addActionListener(e -> processFile(false));
        buttonPanel.add(encryptButton);
        buttonPanel.add(decryptButton);

        add(inputPanel, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);

        setVisible(true);
    }

    private void chooseFile() {
        JFileChooser chooser = new JFileChooser();
        int result = chooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            fileField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void processFile(boolean encrypt) {
        String key = keyField.getText();
        String filePath = fileField.getText();
        String algorithm = (String) algorithmBox.getSelectedItem();

        if (key.isEmpty() || filePath.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please provide both key and file.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        File inputFile = new File(filePath);
        File outputFile = new File(filePath.replace(".txt", "") +
                (encrypt ? "_encrypted.txt" : "_decrypted.txt"));

        try {
            if ("XOR".equals(algorithm)) {
                xorProcess(inputFile, outputFile, key);
            } else {
                aesProcess(inputFile, outputFile, key, encrypt);
            }
            JOptionPane.showMessageDialog(this, "Operation successful:\n" + outputFile.getAbsolutePath());
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Error: " + ex.getMessage(), "Failed", JOptionPane.ERROR_MESSAGE);
            ex.printStackTrace();
        }
    }

    private void xorProcess(File input, File output, String key) throws IOException {
        byte[] keyBytes = key.getBytes();
        int keyLen = keyBytes.length;
        try (FileInputStream fis = new FileInputStream(input);
             FileOutputStream fos = new FileOutputStream(output)) {

            int data, i = 0;
            while ((data = fis.read()) != -1) {
                byte encrypted = (byte) (data ^ keyBytes[i % keyLen]);
                fos.write(encrypted);
                i++;
            }
        }
    }

    private void aesProcess(File input, File output, String password, boolean encrypt) throws Exception {
        byte[] inputBytes = Files.readAllBytes(input.toPath());
        byte[] keyBytes = password.getBytes("UTF-8");

        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        keyBytes = sha.digest(keyBytes);
        keyBytes = Arrays.copyOf(keyBytes, 16); // AES-128
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKey);

        byte[] outputBytes = cipher.doFinal(inputBytes);
        Files.write(output.toPath(), outputBytes);
    }

    // Drag-and-drop file handler
    private class FileDropHandler extends TransferHandler {
        @Override
        public boolean canImport(TransferSupport support) {
            return support.isDataFlavorSupported(DataFlavor.javaFileListFlavor);
        }

        @Override
        public boolean importData(TransferSupport support) {
            try {
                java.util.List<File> files = (java.util.List<File>)
                        support.getTransferable().getTransferData(DataFlavor.javaFileListFlavor);
                if (!files.isEmpty()) {
                    fileField.setText(files.get(0).getAbsolutePath());
                    return true;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return false;
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(FileEncryptorGUI::new);
    }
}
