package com.aiinirii.securityprivacy.des;

import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * @author aiinirii
 */
public class DESEncryptorTest {

    @Test
    public void testEncryptMessage() throws Exception {
        DESEncryptor desEncryptor = new DESEncryptor();
        String result = desEncryptor.encryptMessage("12345678", "12345678", StandardCharsets.UTF_8);
        Assert.assertEquals("ltACiHjVjIk=", result);
    }

    @Test
    public void testEncryptBytes() {

    }

    @Test
    public void testDecryptMessage() throws Exception {
        DESEncryptor desEncryptor = new DESEncryptor();
        String result = desEncryptor.decryptMessage("ltACiHjVjIk=", "12345678", StandardCharsets.UTF_8);
        Assert.assertEquals("12345678", result);
    }

    @Test
    public void testDecryptBytes() {

    }

    @Test
    public void testInitialPermutation() {
        DESEncryptor desEncryptor = new DESEncryptor();
        long actual = desEncryptor
                .initialPermutation(
                        new BigInteger("0110001101101111011011010111000001110101011101000110010101110010", 2).longValue()
                );
        Assert.assertEquals(
                new BigInteger("1111111110111000011101100101011100000000111111110000011010000011", 2).longValue(),
                actual
        );
    }

    @Test
    public void testRotateKey() {
        DESEncryptor desEncryptor = new DESEncryptor();
        long l = desEncryptor.rotateKey(0xFFFFFFE, 2);
        Assert.assertEquals(0xFFFFFFB, l);
    }

    @Test
    public void testGenerateKeyList() {
        DESEncryptor desEncryptor = new DESEncryptor();
        List<Long> keys = desEncryptor.generateSubKeys(0x133457799BBCDFF1L);
        Assert.assertEquals(0x1B02EFFC7072L, keys.get(0).longValue());
        Assert.assertEquals(0xCB3D8B0E17F5L, keys.get(15).longValue());
    }

    @Test
    public void testSubstituteBox() {
        DESEncryptor desEncryptor = new DESEncryptor();
        long sOutput = desEncryptor.substituteBox(0x9B15117CA474L);
        Assert.assertEquals(0x8BC462EAL, sOutput);
    }

    @Test
    public void testEncryptBlock() {
        DESEncryptor desEncryptor = new DESEncryptor();
        long secretMessage = desEncryptor.encryptBlock(0x636F6D7075746572L, desEncryptor.generateSubKeys(0x133457799BBCDFF1L));
        Assert.assertEquals(0x5808300BCDD61868L, secretMessage);
    }
}