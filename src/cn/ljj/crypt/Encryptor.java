package cn.ljj.crypt;

import java.io.File;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

public class Encryptor {
    protected PublicKey mPubKey;

    public Encryptor(byte[] pubKey) throws Exception {
        if (pubKey == null || pubKey.length <= 0) {
            throw new IllegalArgumentException("pubKey can not be empty!");
        }
        generatePublicKey(pubKey);
    }

    protected void generatePublicKey(byte[] pubKey) throws Exception {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(pubKey);
        KeyFactory factory = KeyFactory.getInstance(CritUtils.KEY_ALGORITHM);
        mPubKey = factory.generatePublic(x509EncodedKeySpec);
    }

    public Encryptor(File pubKeyFile) throws Exception {
        this(CritUtils.getFileString(pubKeyFile));
    }

    public byte[] RSAEncrypt(byte[] input) {
        try {
            Cipher cipher = Cipher.getInstance(CritUtils.CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, mPubKey);
            return cipher.doFinal(input);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
