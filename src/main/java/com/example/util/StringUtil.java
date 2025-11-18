package com.example.util;

public class StringUtil {

    private StringUtil() {

    }

    public static boolean isEmpty(String str) {
        return str == null || str.trim().isEmpty();
    }

}
