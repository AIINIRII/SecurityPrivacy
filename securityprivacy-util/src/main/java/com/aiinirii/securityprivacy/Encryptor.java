package com.aiinirii.securityprivacy;

import java.nio.charset.Charset;

public interface Encryptor {
    /**
     * encode using base 64
     * @param message the message to be used
     * @param key the key
     * @param charset the charset to interpret message
     * @return Base64 encoded message
     * @throws Exception
     */
    String encryptMessage(String message, String key, Charset charset) throws Exception;

    /**
     * encrypt the bytes array using key
     * @param bytes bytes array
     * @param key the key
     * @return the bytes array after encrypting
     * @throws Exception
     */
    byte[] encryptBytes(byte[] bytes, String key) throws Exception;

    String decryptMessage(String message, String key, Charset charset) throws Exception;

    byte[] decryptBytes(byte[] bytes, String key) throws Exception;
}
