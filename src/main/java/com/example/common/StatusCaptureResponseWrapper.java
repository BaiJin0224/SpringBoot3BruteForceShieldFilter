package com.example.common;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import java.io.IOException;

public class StatusCaptureResponseWrapper extends HttpServletResponseWrapper {
    private int httpStatus = HttpServletResponse.SC_OK;

    public StatusCaptureResponseWrapper(HttpServletResponse response) {
        super(response);
    }

    @Override
    public void setStatus(int sc) {
        super.setStatus(sc);
        this.httpStatus = sc;
    }

    @Override
    public void sendError(int sc) throws IOException {
        super.sendError(sc);
        this.httpStatus = sc;
    }

    @Override
    public void sendError(int sc, String msg) throws IOException {
        super.sendError(sc, msg);
        this.httpStatus = sc;
    }

    @Override
    public void sendRedirect(String location) throws IOException {
        super.sendRedirect(location);
        this.httpStatus = HttpServletResponse.SC_FOUND;
    }

    public int getStatus() {
        return this.httpStatus;
    }
}
