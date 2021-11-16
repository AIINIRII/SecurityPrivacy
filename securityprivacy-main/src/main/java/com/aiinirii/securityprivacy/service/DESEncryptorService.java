package com.aiinirii.securityprivacy.service;

import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

/**
 * @author aiinirii
 */
public interface DESEncryptorService {

    String encryptFile(MultipartFile file, String key) throws Exception;

    String decryptFile(MultipartFile file, String key) throws Exception;

    String encryptString(String message, String key) throws Exception;

    String decryptString(String message, String key) throws Exception;

}
