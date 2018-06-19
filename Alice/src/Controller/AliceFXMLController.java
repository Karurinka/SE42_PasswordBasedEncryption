package Controller;

import javafx.fxml.FXML;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import javax.swing.*;
import java.awt.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class AliceFXMLController
{
    @FXML
    JPasswordField passwordField;

    @FXML
    TextArea messageField;

    @FXML
    Button btnEncrypt;

    @FXML
    Button btnDecrypt;

    private char[] passwordChars;
    private byte[] messageChars;

    private static final int ITERATION_COUNT = 1000;
    private static final int KEY_SIZE_IN_BITS = 128;
    private static final int IV_SIZE_IN_BITS = 128;
    private static final int TAG_SIZE_IN_BITS = 128;

    private static final String KEY_DERIVATION_FUNCTION = "PBKDF2WithHmacSHA256";
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final String GENERATOR_ALGORITHM = "SHA1PRNG";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    private static SecretKey deriveKey(char[] password, byte[] salt)
    {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, ITERATION_COUNT, KEY_SIZE_IN_BITS);
        SecretKey pbeKey = null;
        byte[] keyBytes = null;

        try
        {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_FUNCTION);
            pbeKey = factory.generateSecret(pbeKeySpec);
            keyBytes = pbeKey.getEncoded();
            return new SecretKeySpec(keyBytes, ENCRYPTION_ALGORITHM);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e)
        {
            throw new AssertionError(e);
        } finally
        {
            try
            {
                pbeKeySpec.clearPassword();

                if (keyBytes != null) Arrays.fill(keyBytes, (byte) 0);

                if (pbeKey != null && !pbeKey.isDestroyed()) pbeKey.destroy();
            }

            // For some reason, you can't destroy PBE keys, but I think it's best to try.
            // We ignore the exception because it's not allowed to propagate exceptions from finally-blocks.
            catch (DestroyFailedException ex) {}
        }
    }

    private static byte[] generateIV()
    {
        try
        {
            SecureRandom random = SecureRandom.getInstance(GENERATOR_ALGORITHM);
            byte[] iv = new byte[IV_SIZE_IN_BITS / 8];
            random.nextBytes(iv);
            return iv;
        }

        // I'm pretty sure SHA1 PRNGs are supported by Java, so this exception should never occur.
        catch (NoSuchAlgorithmException ex)
        {
            throw new AssertionError(ex);
        }
    }

    private static Cipher initCipher(int mode, char[] password, byte[] iv)
    {
        // We're using AES in Galois Counter Mode, here we're preparing the spec.
        // The tag size is the size of the tag that AES-GCM uses to sign and authenticate the encrypted data with.
        // Authentication is important, because it helps us detect that a message wasn't forged by an attacker.
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_SIZE_IN_BITS, iv);

        // As mentioned before, the key is derived using the IV as a salt.
        // This is inappropriate if you store credentials in a database, in that case the IV should only be used for the encryption step
        // and the salt should be stored in the database separately, per key.
        SecretKey key = deriveKey(password, iv);

        try
        {
            // We're using AES in Galois Counter Mode.
            // This transformation is a form of AEAD and performs authentication as well as encryption.
            // Data should never be encrypted without being authenticated.
            // Since GCM is a stream cipher mode and not a block cipher mode, it doesn't require padding.
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(mode, key, gcmSpec);
            return cipher;
        }

        // Again, these exceptions should not occur, since we have tight control over the parameters.
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException ex)
        {
            throw new AssertionError(ex);
        }

        // Try to destroy the key.
        // I'm actually not sure if this is correct, because I don't know whether the cipher still uses it or whether it has its own copy.
        // Difficult to test, because it turns out that you also can't destroy SecretKeySpecs.
        finally
        {
            try
            {
                key.destroy();
            }

            // Don't let exceptions escape from finally-blocks.
            catch (DestroyFailedException ex) {}
        }
    }

    static byte[] encrypt(byte[] message, char[] password)
    {
        try
        {
            byte[] iv = generateIV();

            Cipher cipher = initCipher(Cipher.ENCRYPT_MODE, password, iv);
            byte[] ciphertext = cipher.doFinal(message);

            // The IV needs to be stored with the ciphertext, otherwise we can't decrypt the message later.
            byte[] result = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);

            return result;
        }

        // GCM is a stream mode, so block sizes are irrelevant.
        // BadPaddingException happens during decryption, not during encryption.
        catch (IllegalBlockSizeException | BadPaddingException ex)
        {
            throw new AssertionError(ex);
        }
    }

    static byte[] decrypt(byte[] encrypted, char[] password) throws BadPaddingException
    {
        try
        {
            byte[] iv = Arrays.copyOfRange(encrypted, 0, IV_SIZE_IN_BITS / 8);
            byte[] ciphertext = Arrays.copyOfRange(encrypted, iv.length, encrypted.length);

            Cipher cipher = initCipher(Cipher.DECRYPT_MODE, password, iv);
            byte[] message = cipher.doFinal(ciphertext);

            return message;
        }

        // Block sizes are a property of block ciphers, not stream ciphers.
        catch (IllegalBlockSizeException ex)
        {
            throw new AssertionError(ex);
        }
    }

    public AliceFXMLController()
    {

    }

    @FXML
    public void encryptClicked()
    {
        passwordField = new JPasswordField();
        messageField = new TextArea();

        passwordChars = passwordField.getPassword();
        messageChars = messageField.getText().getBytes();

        encrypt(messageChars, passwordChars);
    }

    @FXML
    public void decryptClicked()
    {

    }
}
