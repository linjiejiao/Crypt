package cn.ljj.crypt;

import java.security.PrivateKey;

import javax.crypto.Cipher;

public class RSADecryptor {
    protected PrivateKey mPrivateKey;

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
