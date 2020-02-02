/*
 * Copyright (c) 2012-2018 Arne Schwabe
 * Distributed under the GNU GPL v2 with additional terms. For full terms see the file doc/LICENSE.txt
 */

package de.blinkt.externalcertprovider;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.StringReader;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class SimpleSigner {
    final static String pemkey = "-----BEGIN PRIVATE KEY-----\n" +
            "-----END PRIVATE KEY-----\n";
    final static String[] certchain = new String[]{"-----BEGIN CERTIFICATE-----\n" +
            "-----END CERTIFICATE-----\n"
            ,
            "-----BEGIN CERTIFICATE-----\n" +
                    "-----END CERTIFICATE-----\n"};

    public static byte[] signData(byte[] data) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // This is more or less code that has been just modified long enough that it works
        // Don't take it as good example how to get a Privatekey
        StringReader keyreader = new StringReader(SimpleSigner.certchain[0] + SimpleSigner.pemkey);
        PEMParser pemparser = new PEMParser(keyreader);

        X509CertificateHolder cert = (X509CertificateHolder) pemparser.readObject();
        PrivateKeyInfo keyInfo = (PrivateKeyInfo) pemparser.readObject();

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyInfo.getEncoded());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey key = kf.generatePrivate(keySpec);

        // The actual signing

        Cipher signer;
        signer = Cipher.getInstance("RSA/ECB/PKCS1PADDING");


        signer.init(Cipher.ENCRYPT_MODE, key);

        byte[] signed_bytes = signer.doFinal(data);
        return signed_bytes;
    }
}
