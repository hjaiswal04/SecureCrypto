package com.example.cryptotest.Utilities;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.asn1.x500.X500Name;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Date;

public class KeyGeneratorUtility {

    // Initialize Bouncy Castle security provider
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // Generate RSA Key Pair using Bouncy Castle
    public KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048);  // RSA with 2048-bit key size
        return keyPairGenerator.generateKeyPair();
    }

    // Generate a self-signed certificate using Bouncy Castle
    public X509Certificate generateSelfSignedCertificate(KeyPair keyPair) throws Exception {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);

        X500Name dnName = new X500Name("CN=Self-Signed Certificate");
        BigInteger certSerialNumber = new BigInteger(Long.toString(now)); // Use a random number for the serial number
        Date endDate = new Date(now + 365 * 24 * 60 * 60 * 1000L); // Valid for 1 year

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic());

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(contentSigner));
    }

    // Generate AES Key using Bouncy Castle
    public SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
        keyGenerator.init(256);  // AES with 256-bit key size
        return keyGenerator.generateKey();
    }

    // AES Encryption with SecretKey (Symmetric Encryption)
    public byte[] aesEncryptData(SecretKey secretKey, String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] iv = cipher.getIV();  // Get the IV for GCM mode
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        byte[] encryptedData = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, encryptedData, 0, iv.length);
        System.arraycopy(ciphertext, 0, encryptedData, iv.length, ciphertext.length);

        return encryptedData;
    }

    // AES Decryption with SecretKey (Symmetric Decryption)
    public String aesDecryptData(SecretKey secretKey, byte[] encryptedData) throws Exception {
        byte[] iv = Arrays.copyOfRange(encryptedData, 0, 12);  // Extract the IV
        byte[] ciphertext = Arrays.copyOfRange(encryptedData, 12, encryptedData.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);  // 128-bit authentication tag
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        byte[] plaintextBytes = cipher.doFinal(ciphertext);
        return new String(plaintextBytes, StandardCharsets.UTF_8);
    }

    // RSA Public Key Encryption (Asymmetric)
    public static byte[] encryptWithPublicKey(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    // RSA Private Key Decryption (Asymmetric)
    public static byte[] decryptWithPrivateKey(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }

    // RSA Private Key Encryption (Signing - Asymmetric)
    public static byte[] encryptWithPrivateKey(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    // RSA Public Key Decryption (Verifying - Asymmetric)
    public static byte[] decryptWithPublicKey(byte[] encryptedData, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(encryptedData);
    }
}
