package cn.ljj.crypt;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

public class DerEncryptor extends Encryptor {

    public DerEncryptor(byte[] pubKey) throws Exception {
        super(pubKey);
    }

    public DerEncryptor(File pubKeyFile) throws Exception {
        super(pubKeyFile);
    }

    protected void generatePublicKey(byte[] pubKey) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        Certificate cert = factory.generateCertificate(new ByteArrayInputStream(pubKey));
        mPubKey = cert.getPublicKey();
    }

}
