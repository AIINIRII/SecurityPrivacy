package com.aiinirii.securityprivacy.service.impl;

import com.aiinirii.securityprivacy.des.DESEncryptor;
import com.aiinirii.securityprivacy.service.DESEncryptorService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * @author aiinirii
 */
@Service
public class DESEncryptorServiceImpl implements DESEncryptorService {

    @Value("${downloadFilePath}")
    private String downloadFilePath;

    @Override
    public String encryptFile(MultipartFile file, String key) throws Exception {

        byte[] bytes = file.getBytes();
        int length = bytes.length;
        byte[] encryptBytes = new DESEncryptor().encryptBytes(bytes, key);
        String filename = file.getOriginalFilename() + ".crypted";

        File downloadFolder = new File(downloadFilePath);
        if (!downloadFolder.exists()) {
            downloadFolder.mkdir();
        }

        File downloadFile = new File(downloadFilePath + filename);
        if (!downloadFile.exists()) {
            downloadFile.createNewFile();
        }

        FileOutputStream fileOutputStream = new FileOutputStream(downloadFile);
        fileOutputStream.write((length >> 24) & 0x000000FF);
        fileOutputStream.write((length >> 16) & 0x000000FF);
        fileOutputStream.write((length >> 8) & 0x000000FF);
        fileOutputStream.write(length & 0x000000FF);
        fileOutputStream.write(encryptBytes);
        fileOutputStream.flush();
        fileOutputStream.close();
        return filename;
    }

    @Override
    public String decryptFile(MultipartFile file, String key) throws Exception {
        String filename = null;
        String originalFilename = file.getOriginalFilename();
        if (Objects.requireNonNull(originalFilename).contains(".crypted")) {
            filename = originalFilename.replace(".crypted", "");
        }

        byte[] bytes = file.getBytes();
        int length = ((bytes[0] << 24) & 0xFF000000) | ((bytes[1] << 16) & 0x00FF0000) | ((bytes[2] << 8) & 0x0000FF00) | ((bytes[3]) & 0x000000FF);
        byte[] decryptBytes = new byte[length];
        for (int i = 4; i < bytes.length; i++) {
            decryptBytes[i - 4] = bytes[i];
        }

        byte[] decryptedBytes = new DESEncryptor().decryptBytes(decryptBytes, key);
        File downloadFile = new File(downloadFilePath + filename);
        if (!downloadFile.exists()) {
            downloadFile.createNewFile();
        }
        FileOutputStream fileOutputStream = new FileOutputStream(downloadFile);
        fileOutputStream.write(decryptedBytes);
        fileOutputStream.flush();
        fileOutputStream.close();
        return filename;
    }

    @Override
    public String encryptString(String message, String key) throws Exception {
        return new DESEncryptor().encryptMessage(message, key, StandardCharsets.UTF_8);
    }

    @Override
    public String decryptString(String message, String key) throws Exception {
        return new DESEncryptor().decryptMessage(message, key, StandardCharsets.UTF_8);
    }

}
