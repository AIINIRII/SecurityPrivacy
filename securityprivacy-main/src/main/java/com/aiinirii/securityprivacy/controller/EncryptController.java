package com.aiinirii.securityprivacy.controller;

import com.aiinirii.securityprivacy.service.DESEncryptorService;
import com.aiinirii.securityprivacy.service.FileDownloadService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author aiinirii
 */
@Controller
public class EncryptController {

    private DESEncryptorService desEncryptorService;

    private FileDownloadService fileDownloadService;


    @Autowired
    public void setDesEncryptorService(DESEncryptorService desEncryptorService) {
        this.desEncryptorService = desEncryptorService;
    }

    @Autowired
    public void setFileDownloadService(FileDownloadService fileDownloadService) {
        this.fileDownloadService = fileDownloadService;
    }

    @RequestMapping("/")
    public String indexPage() {
        return "index";
    }

    @PostMapping("/encryptFile")
    @ResponseBody
    public String encryptFile(@RequestParam("file") MultipartFile file, @RequestParam("key") String key) throws Exception {
        // encrypt file
        return desEncryptorService.encryptFile(file, key);
    }

    @PostMapping("/decryptFile")
    @ResponseBody
    public String decryptFile(@RequestParam("file") MultipartFile file, @RequestParam("key") String key) throws Exception {
        // decrypt file
        return desEncryptorService.decryptFile(file, key);
    }
    @PostMapping("/encryptText")
    @ResponseBody
    public String encryptText(@RequestParam("message") String message, @RequestParam("key") String key) throws Exception {
        // encrypt text
        return desEncryptorService.encryptString(message, key);
    }

    @PostMapping("/decryptText")
    @ResponseBody
    public String decryptText(@RequestParam("message") String message, @RequestParam("key") String key) throws Exception {
        // decrypt text
        return desEncryptorService.decryptString(message, key);
    }

    @RequestMapping("/downloadFile/{fileName}")
    @ResponseBody
    public String downloadFile(@PathVariable("fileName") String fileName, HttpServletRequest request, HttpServletResponse response) {
        fileDownloadService.downloadFile(fileName, response);
        return null;
    }

}
