package com.aiinirii.securityprivacy.service;

import javax.servlet.http.HttpServletResponse;

/**
 * @author aiinirii
 */
public interface FileDownloadService {

    void downloadFile(String fileName, HttpServletResponse response);
}
