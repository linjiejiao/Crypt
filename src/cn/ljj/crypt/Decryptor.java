package cn.ljj.crypt;

import java.io.File;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;

public class Decryptor extends RSADecryptor {

    public Decryptor(byte[] privateKey) throws Exception {
        if (privateKey == null || privateKey.length <= 0) {
            throw new IllegalArgumentException("pubKey can not be empty!");
        }
        generatePrivateKey(privateKey);
    }

    public Decryptor(File rivateKeyFile) throws Exception {
        this(CryptUtils.getFileString(rivateKeyFile));
    }

    protected void generatePrivateKey(byte[] privateKey) throws Exception {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey);
        KeyFactory factory = KeyFactory.getInstance(CryptUtils.KEY_ALGORITHM);
        mPrivateKey = factory.generatePrivate(pkcs8EncodedKeySpec);
    }
}
