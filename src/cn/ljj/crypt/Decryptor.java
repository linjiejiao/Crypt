package cn.ljj.crypt;

import java.io.File;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;

public class Decryptor {
    private PrivateKey mPrivateKey;

    public Decryptor(byte[] privateKey) throws Exception {
        if (privateKey == null || privateKey.length <= 0) {
            throw new IllegalArgumentException("pubKey can not be empty!");
        }
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey);
        KeyFactory factory = KeyFactory.getInstance(CritUtils.KEY_ALGORITHM);
        mPrivateKey = factory.generatePrivate(pkcs8EncodedKeySpec);
    }

    public Decryptor(File rivateKeyFile) throws Exception {
        this(CritUtils.getFileString(rivateKeyFile));
    }

    public byte[] RSADecrypt(byte[] encodedText) {
        try {
            Cipher cipher = Cipher.getInstance(CritUtils.CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, mPrivateKey);
            return cipher.doFinal(encodedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
