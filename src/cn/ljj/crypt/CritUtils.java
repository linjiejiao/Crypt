package cn.ljj.crypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class CritUtils {
    public static final String KEY_ALGORITHM = "RSA";
    public static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";
    public static final int KEY_SIZE = 2048;

    public static byte[] getFileString(File file) {
        if (file == null || !file.exists()) {
            return null;
        }
        try {
            InputStream inputStream = new FileInputStream(file);
            int size = inputStream.available();
            byte[] buffer = new byte[size];
            inputStream.read(buffer);
            inputStream.close();
            return buffer;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static KeyPair generateKeyPairs() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
            keyPairGenerator.initialize(KEY_SIZE);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static boolean generateKeyPairsToPath(String folder) {
        KeyPair keyPair = generateKeyPairs();
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        File publicKeyFile = new File(folder, "rsa.pub");
        FileOutputStream publicKeyFileOutputStream = null;
        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
        File privateKeyFile = new File(folder, "rsa");
        FileOutputStream privateKeyFileOutputStream = null;
        try {
            publicKeyFileOutputStream = new FileOutputStream(publicKeyFile);
            publicKeyFileOutputStream.write(publicKeyBytes);
            privateKeyFileOutputStream = new FileOutputStream(privateKeyFile);
            privateKeyFileOutputStream.write(privateKeyBytes);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            publicKeyFile.delete();
            privateKeyFile.delete();
        } finally {
            if (publicKeyFileOutputStream != null) {
                try {
                    publicKeyFileOutputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (privateKeyFileOutputStream != null) {
                try {
                    privateKeyFileOutputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return false;
    }
}
