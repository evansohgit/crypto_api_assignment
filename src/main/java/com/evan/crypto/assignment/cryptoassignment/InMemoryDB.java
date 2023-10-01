package com.evan.crypto.assignment.cryptoassignment;

import java.util.HashMap;
import java.util.Map;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/*
 * python dict to replicate as static class in java
 * app_db = {
    'admin_app': {
        'api_key': 'admin',
        'api_token': 'admin',
        'is_admin': True,
        'secret_keys': 
            {'admin_secret_1': Fernet.generate_key().decode('utf-8'),}
        
    },
    'test_app': {
        'api_key': 'test',
        'api_token': 'test',
        'is_admin': False,
        'secret_keys': {
            'test_secret_1': 'key2',
        }

    }
}

 */
public class InMemoryDB {


    public static Map<String, Map<String, Object>> appDatabase = new HashMap<>();

    static{
        try{
            Map<String, Object> adminApp = new HashMap<>();
            adminApp.put("api_key", "admin");
            adminApp.put("api_token", "admin");
            adminApp.put("is_admin", true);

            Map<String, SecretKey> adminSecretKeys = new HashMap<>();
            adminSecretKeys.put("admin_secret_1", KeyGenerator.getInstance("AES").generateKey()); // Replace with your actual secret key
            adminApp.put("secret_keys", adminSecretKeys);

            Map<String, Object> testApp = new HashMap<>();
            testApp.put("api_key", "test");
            testApp.put("api_token", "test");
            testApp.put("is_admin", false);

            Map<String, SecretKey> testSecretKeys = new HashMap<>();
            testSecretKeys.put("test_secret_1", KeyGenerator.getInstance("AES").generateKey());
            testApp.put("secret_keys", testSecretKeys);
            // Add the apps to the database
            appDatabase.put("admin_app", adminApp);
            appDatabase.put("test_app", testApp);
        }
        catch(Exception e){
            System.out.println(e);
        }
        




    }

    // get app given an app name
    public static Map<String, Object> getAppByName(String appName){
        return appDatabase.get(appName);
    }

    // get app given api key and api token
    public static Map<String, Object> getAppByKeyToken(String apiKey, String apiToken){
        for (Map.Entry<String, Map<String, Object>> entry : appDatabase.entrySet()) {
            Map<String, Object> app = entry.getValue();
            if (app.get("api_key").equals(apiKey) && app.get("api_token").equals(apiToken)) {
                return app;
            }
        }
        return null;
    }

    public  void addKeyToApp(String appName, String secretKeyName, SecretKey secretKey){
        Map<String, Object> app = appDatabase.get(appName);
        Map<String, SecretKey> secretKeys = (Map<String, SecretKey>) app.get("secret_keys");
        secretKeys.put(secretKeyName, secretKey);
    }

    public void addNewApp(String appName){
        Map<String, Object> newApp = new HashMap<>();
        newApp.put("api_key", appName);
        newApp.put("api_token", appName);
        newApp.put("is_admin", false);
        Map<String, SecretKey> secretKeys = new HashMap<>();
        newApp.put("secret_keys", secretKeys);
        appDatabase.put(appName, newApp);
    }
    



    
}

