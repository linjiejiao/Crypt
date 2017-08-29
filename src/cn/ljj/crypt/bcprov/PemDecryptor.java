package cn.ljj.crypt.bcprov;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PasswordFinder;

import cn.ljj.crypt.RSADecryptor;

public class PemDecryptor extends RSADecryptor {

    public PemDecryptor(File rivateKeyFile, String password) throws Exception {
        if (rivateKeyFile == null) {
            throw new IllegalArgumentException("rivateKeyFile can not be empty!");
        }
        FileInputStream inputStream = new FileInputStream(rivateKeyFile);
        Security.addProvider(new BouncyCastleProvider());
        PEMReader reader = new PEMReader(new InputStreamReader(inputStream), new PasswordFinder() {
            @Override
            public char[] getPassword() {
                return password.toCharArray();
            }
        });
        KeyPair keyPair = (KeyPair) reader.readObject();
        reader.close();
        mPrivateKey = keyPair.getPrivate();
    }

}
