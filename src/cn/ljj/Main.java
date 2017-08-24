package cn.ljj;

import java.io.File;
import java.util.Base64;

import cn.ljj.crypt.CritUtils;
import cn.ljj.crypt.Decryptor;
import cn.ljj.crypt.Encryptor;

public class Main {

    public static void main(String[] args) {
        String home = System.getProperty("user.home");
        CritUtils.generateKeyPairsToPath(home);
        try {
            byte[] original = "qwertyuiop".getBytes();
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
    }

}
