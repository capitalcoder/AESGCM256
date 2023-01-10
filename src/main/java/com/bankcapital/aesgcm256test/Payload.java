package com.bankcapital.aesgcm256test;

public class Payload {
    String message;
    String iv;

    String key;

    public Payload() {}

    public Payload(String message, String key, String iv) {}

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }
}
