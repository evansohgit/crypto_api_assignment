package com.evan.crypto.assignment.cryptoassignment;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CryptoController {

    @PostMapping("/encrypt")
    public ResponseEntity<Object> encrypt(@RequestHeader("api-key") String apiKey,
            @RequestParam("app-name") String appName,
            @RequestParam("secret-key-name") String secretKeyName,
            @RequestParam("data") String data) {

        Map<String, Object> app = InMemoryDB.getAppByName(appName);
        if (appName == null || appName == "") {
            return new ResponseEntity<Object>("App Name required", null, 400);
        }
        if (app == null) {
            return new ResponseEntity<Object>("App not found", null, 400);
        }
        // Raise error if secret key does not exist
        Map<String, SecretKey> secretKeys = (Map<String, SecretKey>) app.get("secret_keys");
        if (!secretKeys.containsKey(secretKeyName)) {
            return new ResponseEntity<Object>("Secret key not found", null, 400);
        }

        try {
            SecretKey secretKey = secretKeys.get(secretKeyName);
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedData = cipher.doFinal(data.getBytes());
            return new ResponseEntity<>(Base64.getEncoder().encodeToString(encryptedData), HttpStatus.OK);

        } catch (Exception e) {
            System.out.println(e);
            return new ResponseEntity<Object>("Error encrypting data", null, 500);
        }

    }

    @PostMapping("/decrypt")
    public ResponseEntity<Object> decrypt(@RequestParam("app-name") String appName,
            @RequestParam("secret-key-name") String secretKeyName,
            @RequestParam("data") String data) {
        /*
         * Decrypt data using secret key. Raise error if secret key does not exist
         */
        Map<String, Object> app = InMemoryDB.getAppByName(appName);
        if (appName == null || appName == "") {
            return new ResponseEntity<Object>("App Name required", null, 400);
        }
        if (app == null) {
            return new ResponseEntity<Object>("App not found", null, 400);
        }
        // Raise error if secret key does not exist
        Map<String, SecretKey> secretKeys = (Map<String, SecretKey>) app.get("secret_keys");
        if (!secretKeys.containsKey(secretKeyName)) {
            return new ResponseEntity<Object>("Secret key not found", null, 400);
        }
        try {
            SecretKey secretKey = secretKeys.get(secretKeyName);
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(data));
            return new ResponseEntity<>(new String(decryptedData), HttpStatus.OK);
        } catch (Exception e) {
            System.out.println(e);
            return new ResponseEntity<Object>("Error encrypting data", null, 500);
        }

    }

    @PostMapping("/onboardApp")
    public ResponseEntity<Object> onboardApp(@RequestParam("app-name") String appName) {
        /*
         * Adds new app to DB
         */
        InMemoryDB db = new InMemoryDB();
        Map<String, Object> app = db.getAppByName(appName);
        if (app != null) {
            return new ResponseEntity<Object>("App already exists", null, 400);
        }

        db.addNewApp(appName);
        return new ResponseEntity<Object>("App onboarded", null, 200);

    }

    @PostMapping("/createSecretKey")
    public ResponseEntity<Object> createSecretKey(
            @RequestParam("app-name") String appName,
            @RequestParam("secret-key-name") String secretKeyName) throws NoSuchAlgorithmException {
        /*
         * Create a secret key for the app. Raise error if app already has a secret with
         * same key name
         */
        Map<String, Object> app = InMemoryDB.getAppByName(appName);
        if (appName == null || appName == "") {
            return new ResponseEntity<Object>("App Name required", null, 400);
        }
        if (app == null) {
            return new ResponseEntity<Object>("App not found", null, 400);
        }
        Map<String, SecretKey> secretKeys = (Map<String, SecretKey>) app.get("secret_keys");

        // Raise error if secret key already exists
        if (secretKeys.containsKey(secretKeyName)) {
            return new ResponseEntity<Object>("Secret key already exists", null, 400);
        }

        // Generate secret key and add to app. Key to be used in SecretKeySpec
        InMemoryDB db = new InMemoryDB();
        db.addKeyToApp(appName, secretKeyName, KeyGenerator.getInstance("AES").generateKey());
        return new ResponseEntity<Object>("Secret key created", null, 200);

    }

    @PostMapping("/test")
    public String test() {
        InMemoryDB db = new InMemoryDB();
        // Print db
        for (Map.Entry<String, Map<String, Object>> entry : db.appDatabase.entrySet()) {
            System.out.println(entry.getKey() + "/" + entry.getValue());
        }
        return "DB printed onto sysout";
    }
}
