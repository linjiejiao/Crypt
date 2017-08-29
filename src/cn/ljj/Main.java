package cn.ljj;

import java.io.File;
import java.util.Base64;

import cn.ljj.crypt.CryptUtils;
import cn.ljj.crypt.Decryptor;
import cn.ljj.crypt.DerEncryptor;
import cn.ljj.crypt.Encryptor;
import cn.ljj.crypt.bcprov.BcprovUtils;
import cn.ljj.crypt.bcprov.PemDecryptor;

public class Main {

    /***
     * openssl req -x509 -out public_key.der -outform der -new -newkey rsa:2048
     * -keyout private_key.pem -days 3650
     * 
     * @param args
     */
    public static void main(String[] args) {
        String home = System.getProperty("user.home");
        if (!new File(home, "rsa.pub").exists()) {
            CryptUtils.generateKeyPairsToPath(home);
            System.out.println("generateKeyPairsToPath:" + home);
        }
        File pemFile = new File(home + File.separator + "private_key.pem");
        if (pemFile.exists()) {
            try {
                BcprovUtils.decodePem(pemFile.getAbsolutePath(), "123456");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        try {
            byte[] original = "qwertyuiop".getBytes();
            System.out.println("original.length=" + original.length);
            System.out.println("original=" + Base64.getEncoder().encodeToString(original));
            byte[] encrypted = new DerEncryptor(new File(home, "public_key.der")).RSAEncrypt(original);
            System.out.println("encrypted.length=" + encrypted.length);
            System.out.println("encrypted=" + Base64.getEncoder().encodeToString(encrypted));
            byte[] decrypted = new PemDecryptor(new File(home, "private_key.pem"), "123456").RSADecrypt(encrypted);
            System.out.println("decrypted.length=" + decrypted.length);
            System.out.println("decrypted=" + Base64.getEncoder().encodeToString(decrypted));
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("\n====================");
        try {
            home = home + File.separator + "private_key";
            byte[] original = "asdfghjkl".getBytes();
            System.out.println("original.length=" + original.length);
            System.out.println("original=" + Base64.getEncoder().encodeToString(original));
            byte[] encrypted = new Encryptor(new File(home, "rsa.pub")).RSAEncrypt(original);
            System.out.println("encrypted.length=" + encrypted.length);
            System.out.println("encrypted=" + Base64.getEncoder().encodeToString(encrypted));
            byte[] decrypted = new Decryptor(new File(home, "rsa")).RSADecrypt(encrypted);
            System.out.println("decrypted.length=" + decrypted.length);
            System.out.println("decrypted=" + Base64.getEncoder().encodeToString(decrypted));
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("\n====================");
        byte[] original = "zxcvbnm".getBytes();
        System.out.println("original.length=" + original.length);
        System.out.println("original=" + Base64.getEncoder().encodeToString(original));
        byte[] encrypted = CryptUtils.symmetricalEncrypt(original, "123456".getBytes());
        System.out.println("encrypted.length=" + encrypted.length);
        System.out.println("encrypted=" + Base64.getEncoder().encodeToString(encrypted));
        byte[] decrypted = CryptUtils.symmetricalDecrypt(encrypted, "123456".getBytes());
        System.out.println("decrypted.length=" + decrypted.length);
        System.out.println("decrypted=" + Base64.getEncoder().encodeToString(decrypted));
    }

}
