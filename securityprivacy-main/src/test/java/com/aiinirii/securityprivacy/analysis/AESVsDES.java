package com.aiinirii.securityprivacy.analysis;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.util.StopWatch;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;

/**
 * This test class is used to test how efficient AES comparing with DES
 *
 * @author aiinirii
 */
@SpringBootTest
public class AESVsDES {

    @Test
    public void testAESvsDESvsRSAUsingText() throws Exception {
        KeyPair keyRSA = generateRSAKey("defaultKey");
        SecretKeySpec keyAES = generateAESOrDESKey(128, "AES", "defaultKey");
        SecretKeySpec keyDES = generateAESOrDESKey(56, "DES", "defaultKey");

        Cipher cipherAESECB = Cipher.getInstance("AES/ECB/PKCS5Padding");

        Cipher cipherDESECB = Cipher.getInstance("DES/ECB/PKCS5Padding");

        Cipher cipherRSAECB = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        byte[] textBytes;

        initEncryptor(cipherAESECB, keyAES);

        initEncryptor(cipherDESECB, keyDES);

        initRSAEncryptor(cipherRSAECB, keyRSA);

        System.out.println("====== Loading File =======");

        textBytes = "Decrypt Text".getBytes(StandardCharsets.UTF_8);

        System.out.println("====== Done Loading =======");

        StopWatch stopWatch = new StopWatch("AES vs. DES vs. RSA with single file.");


        // AES
        System.out.println("====== Start Testing AES =======");

        stopWatch.start("AES Algorithm with ECB mode");
        cipherAESECB.doFinal(textBytes);
        stopWatch.stop();

        System.out.println("====== End Testing AES =======");

        // DES
        System.out.println("====== Start Testing DES =======");

        stopWatch.start("DES Algorithm with ECB mode");
        cipherDESECB.doFinal(textBytes);
        stopWatch.stop();

        System.out.println("====== End Testing DES =======");

        // RSA
        System.out.println("====== Start Testing RSA =======");

        stopWatch.start("RSA Algorithm with ECB mode");
        cipherRSAECB.doFinal(textBytes);
        stopWatch.stop();

        System.out.println("====== End Testing RSA =======");

        System.out.println(stopWatch.prettyPrint());
    }

    @Test
    public void testAESvsDESUsingFile() throws Exception {

        SecretKeySpec keyAES = generateAESOrDESKey(128, "AES", "defaultKey");
        SecretKeySpec keyDES = generateAESOrDESKey(56, "DES", "defaultKey");

        Cipher cipherAESCBC = Cipher.getInstance("AES/CBC/PKCS5Padding");
        Cipher cipherAESECB = Cipher.getInstance("AES/ECB/PKCS5Padding");
        Cipher cipherAESCFB = Cipher.getInstance("AES/CFB/PKCS5Padding");
        Cipher cipherAESOFB = Cipher.getInstance("AES/OFB/PKCS5Padding");
        Cipher cipherAESCTR = Cipher.getInstance("AES/CTR/PKCS5Padding");

        Cipher cipherDESCBC = Cipher.getInstance("DES/CBC/PKCS5Padding");
        Cipher cipherDESECB = Cipher.getInstance("DES/ECB/PKCS5Padding");
        Cipher cipherDESCFB = Cipher.getInstance("DES/CFB/PKCS5Padding");
        Cipher cipherDESOFB = Cipher.getInstance("DES/OFB/PKCS5Padding");
        Cipher cipherDESCTR = Cipher.getInstance("DES/CTR/PKCS5Padding");

        byte[] gbFileBytes;

        initEncryptor(cipherAESCBC, keyAES);
        initEncryptor(cipherAESECB, keyAES);
        initEncryptor(cipherAESCFB, keyAES);
        initEncryptor(cipherAESOFB, keyAES);
        initEncryptor(cipherAESCTR, keyAES);

        initEncryptor(cipherDESCBC, keyDES);
        initEncryptor(cipherDESECB, keyDES);
        initEncryptor(cipherDESCFB, keyDES);
        initEncryptor(cipherDESOFB, keyDES);
        initEncryptor(cipherDESCTR, keyDES);

        System.out.println("====== Loading File =======");

        gbFileBytes = loadFile();

        System.out.println("====== Done Loading =======");

        StopWatch stopWatch = new StopWatch("AES vs. DES with single file.");


        // AES
        System.out.println("====== Start Testing AES =======");

        stopWatch.start("AES Algorithm with CBC mode");
        cipherAESCBC.doFinal(gbFileBytes);
        stopWatch.stop();

        stopWatch.start("AES Algorithm with ECB mode");
        cipherAESECB.doFinal(gbFileBytes);
        stopWatch.stop();

        stopWatch.start("AES Algorithm with CFB mode");
        cipherAESCFB.doFinal(gbFileBytes);
        stopWatch.stop();

        stopWatch.start("AES Algorithm with OFB mode");
        cipherAESOFB.doFinal(gbFileBytes);
        stopWatch.stop();

        stopWatch.start("AES Algorithm with CTR mode");
        cipherAESCTR.doFinal(gbFileBytes);
        stopWatch.stop();

        System.out.println("====== End Testing AES =======");

        // DES
        System.out.println("====== Start Testing DES =======");

        stopWatch.start("DES Algorithm with CBC mode");
        cipherDESCBC.doFinal(gbFileBytes);
        stopWatch.stop();

        stopWatch.start("DES Algorithm with ECB mode");
        cipherDESECB.doFinal(gbFileBytes);
        stopWatch.stop();

        stopWatch.start("DES Algorithm with CFB mode");
        cipherDESCFB.doFinal(gbFileBytes);
        stopWatch.stop();

        stopWatch.start("DES Algorithm with OFB mode");
        cipherDESOFB.doFinal(gbFileBytes);
        stopWatch.stop();

        stopWatch.start("DES Algorithm with CTR mode");
        cipherDESCTR.doFinal(gbFileBytes);
        stopWatch.stop();

        System.out.println("====== End Testing DES =======");

        System.out.println(stopWatch.prettyPrint());
    }


    private void initRSAEncryptor(Cipher cipher, KeyPair keyPair) throws InvalidKeyException {
        PublicKey publicKey = keyPair.getPublic();

        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

    }

    private void initRSADecryptor(Cipher cipher, KeyPair keyPair) throws InvalidKeyException {
        PublicKey publicKey = keyPair.getPublic();

        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    }

    private KeyPair generateRSAKey(String keySeed) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGeneratorAES = KeyPairGenerator.getInstance("RSA");
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        secureRandom.setSeed(keySeed.getBytes(StandardCharsets.UTF_8));
        keyGeneratorAES.initialize(1024, secureRandom);
        return keyGeneratorAES.generateKeyPair();
    }

    private byte[] loadFile() throws IOException {
        byte[] gbFileBytes;
        File gbFile = new File("..\\data\\1GBFILE.mkv");
        FileInputStream fileInputStream = new FileInputStream(gbFile);
        gbFileBytes = fileInputStream.readAllBytes();
        return gbFileBytes;
    }

    private void initEncryptor(Cipher cipher, SecretKeySpec keySpec) throws Exception {
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
    }

    private SecretKeySpec generateAESOrDESKey(int keySize, String algorithm, String keySeed) throws NoSuchAlgorithmException {
        KeyGenerator keyGeneratorAES = KeyGenerator.getInstance(algorithm);
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        secureRandom.setSeed(keySeed.getBytes(StandardCharsets.UTF_8));
        keyGeneratorAES.init(keySize, secureRandom);
        SecretKey secretKeyAES = keyGeneratorAES.generateKey();
        SecretKeySpec secretKeySpecAES = new SecretKeySpec(secretKeyAES.getEncoded(), algorithm);
        return secretKeySpecAES;
    }

    private void initDecryptor(Cipher cipher, SecretKeySpec keySpec) throws Exception {
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
    }
}
