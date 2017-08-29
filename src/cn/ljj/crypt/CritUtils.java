package cn.ljj.crypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PasswordFinder;

public class CritUtils {
    public static final String KEY_ALGORITHM = "RSA";
    public static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";
    public static final int KEY_SIZE = 2048;

    public static byte[] getFileString(File file) {
        if (file == null || !file.exists()) {
            System.err.println("getFileString file=" + file);
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
        return saveKeyPairToFolder(keyPair, folder);
    }

    private static boolean saveKeyPairToFolder(KeyPair keyPair, String folder) {
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

    public static boolean decodePem(String pemPath, String password) throws Exception {
        File file = new File(pemPath);
        FileInputStream inputStream = new FileInputStream(file);
        Security.addProvider(new BouncyCastleProvider());
        PEMReader reader = new PEMReader(new InputStreamReader(inputStream), new PasswordFinder() {
            @Override
            public char[] getPassword() {
                return password.toCharArray();
            }
        });
        KeyPair keyPair = (KeyPair) reader.readObject();
        reader.close();
        String outFolder = file.getAbsolutePath();
        if(file.getName().contains(".")){
            outFolder = pemPath.substring(0, pemPath.lastIndexOf("."));
        }
        new File(outFolder).mkdirs();
        return saveKeyPairToFolder(keyPair, outFolder);
    }
}
