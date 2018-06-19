package Controller;

import Logic.Logic;
import javafx.fxml.FXML;
import javafx.scene.control.PasswordField;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class AliceFXMLController
{
    @FXML
    PasswordField passwordField;

    @FXML
    javafx.scene.control.TextArea messageField;

    @FXML
    javafx.scene.control.Button btnEncrypt;

    @FXML
    javafx.scene.control.Button btnDecrypt;

    private char[] passwordChars;
    private byte[] messageChars;
    private Logic logic;

    public AliceFXMLController()
    {
        passwordField = new PasswordField();
        messageField = new javafx.scene.control.TextArea();
        logic = new Logic();
    }

    @FXML
    public void encryptClicked()
    {
        passwordChars = passwordField.getText().toCharArray();
        messageChars = messageField.getText().getBytes();

        try (FileOutputStream fos = new FileOutputStream ("encrypted"))
        {
            fos.write(logic.encrypt(messageChars, passwordChars));

        } catch (IOException e)
        {
            e.printStackTrace();
        }
        messageField.setText(" ");
    }

    @FXML
    public void decryptClicked()
    {
         passwordChars = passwordField.getText().toCharArray();

        try
        {
            byte[] encryptedMessage = Files.readAllBytes(Paths.get("encrypted"));

            String message = new String(logic.decrypt(encryptedMessage, passwordChars));
            messageField.setText(message);


        } catch (IOException | BadPaddingException e)
        {
            e.printStackTrace();
        }
    }
}
