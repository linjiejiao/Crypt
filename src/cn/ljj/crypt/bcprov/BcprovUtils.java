package cn.ljj.crypt.bcprov;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PasswordFinder;

import cn.ljj.crypt.CryptUtils;

public class BcprovUtils {

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
        if (file.getName().contains(".")) {
            outFolder = pemPath.substring(0, pemPath.lastIndexOf("."));
        }
        new File(outFolder).mkdirs();
        return CryptUtils.saveKeyPairToFolder(keyPair, outFolder);
    }
}
