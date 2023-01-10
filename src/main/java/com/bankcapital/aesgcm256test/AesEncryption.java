package com.bankcapital.aesgcm256test;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;

@RestController
public class AesEncryption {

    Logger logger = LoggerFactory.getLogger(AesEncryption.class);

    private byte[] iv;
    private byte[] key;

    @PostMapping("/encode")
    public String encode(@RequestBody Payload payload) {
        convertToByte(payload.getKey(), payload.getIv());
        return encryptRequest(payload.getMessage(), this.key, this.iv);
    }

    @PostMapping("/decode")
    public String decode(@RequestBody Payload payload) {
        convertToByte(payload.getIv(), payload.getKey());
        return decryptRequest(payload.getMessage(),this.key, this.iv);
    }

    private void convertToByte(String iv, String key) {
        this.iv = Base64.decode(iv);
        this.key = Base64.decode(key);
    }

    private String decryptRequest(String plainText, byte[] key, byte[] iv) {
        String sR = "";
        logger.info("Text: " + plainText);
        try {
            byte[] encryptedBytes = Base64.decode(plainText);

            GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
            AEADParameters parameters = new AEADParameters(new KeyParameter(key), 128, iv, null);

            cipher.init(false, parameters);
            byte[] plainBytes = new byte[cipher.getOutputSize(encryptedBytes.length)];
            int retLen = cipher.processBytes(encryptedBytes, 0, encryptedBytes.length, plainBytes, 0);
            cipher.doFinal(plainBytes, retLen);

            sR = new String(plainBytes, StandardCharsets.UTF_8);
            return sR;
        } catch (IllegalArgumentException | IllegalStateException | DataLengthException | InvalidCipherTextException ex) {
            System.out.println(ex.getMessage());
        }
        return sR;
    }

    private String encryptRequest(String plainText, byte[] key, byte[] iv) {
        String sR = "";
        try {
            byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);

            GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
            AEADParameters parameters = new AEADParameters(new KeyParameter(key), 128, iv, null);

            cipher.init(true, parameters);

            byte[] encryptedBytes = new byte[cipher.getOutputSize(plainBytes.length)];
            int retLen = cipher.processBytes(plainBytes, 0, plainBytes.length, encryptedBytes, 0);
            cipher.doFinal(encryptedBytes, retLen);
            sR = Base64.toBase64String(encryptedBytes);
        } catch (IllegalArgumentException | IllegalStateException | DataLengthException | InvalidCipherTextException ex) {
            System.out.println(ex.getMessage());
        }
        return sR;
    }
}
