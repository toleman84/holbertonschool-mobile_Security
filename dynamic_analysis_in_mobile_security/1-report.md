
# 🛡️ Dynamic Analysis Report: Hooking Native Functions via Frida

## 📝 Project Title
Hooking and Extracting Native Flag from Android App via JNI

## 📦 APK Details
- **APK Name:** `task1_d.apk`
- **Package Name:** `com.holberton.challengeapp`
- **Main Activity:** `com.holberton.challengeapp.MainActivity`
- **Target Library:** `libnative-lib.so`

---

## 🎯 Objective
Perform a dynamic analysis of an Android app using **Frida** to hook a **native JNI function**, modify its behavior if needed, and extract a **decrypted flag** that is processed in native code but never shown in the UI.

---

## 🛠️ Environment Setup

| Tool              | Version | Notes                                 |
|-------------------|---------|----------------------------------------|
| Android Emulator  | API 30  | Rooted with writable system            |
| Frida             | 16.x    | Installed on both PC and emulator      |
| Objection         | Latest  | Wrapper over Frida for easy injection  |
| ADB               | 1.0.41  | Communication with the emulator        |
| JADX              | 1.4.x   | Static analysis of APK                 |
| Kali Linux        | Rolling | Analysis OS                            |

---

## 🔍 Step-by-Step Analysis

### 1. Analyze App Behavior
- Installed the APK:
  ```bash
  adb install task1_d.apk
  ```

- Launched the app: UI shows a button **"Reveal Secret"**, but no output.

- Checked logs with:
  ```bash
  adb logcat | grep com.holberton.challengeapp
  ```

- No useful output—flag handling likely done in native code.

---

### 2. Identify Native Libraries
- Decompiled APK:
  ```bash
  apktool d task1_d.apk
  ```

- Found native library:
  ```
  /lib/armeabi-v7a/libnative-lib.so
  ```

- Decompiled Java with `jadx`, found:
  ```java
  static {
      System.loadLibrary("native-lib");
  }

  public native String getSecretMessage();
  ```

---

### 3. Enumerate Native Functions with Frida
- Attached to running app:
  ```bash
  frida -U -n com.holberton.challengeapp -n
  ```

- Listed native symbols:
  ```js
  Module.enumerateExports("libnative-lib.so").forEach(function(sym) {
      if (sym.name.indexOf("getSecretMessage") !== -1) {
          console.log(sym.name);
      }
  });
  ```

- Output:
  ```
  Java_com_holberton_challengeapp_MainActivity_getSecretMessage
  ```

---

### 4. Hook Native Function with Frida

Created `hook.js`:

```js
Java.perform(function () {
    var MainActivity = Java.use("com.holberton.challengeapp.MainActivity");

    MainActivity.getSecretMessage.implementation = function () {
        var result = this.getSecretMessage();
        console.log("[*] Hooked getSecretMessage(): " + result);
        return result;
    };
});
```

- Ran script:
  ```bash
  frida -U -n com.holberton.challengeapp -l hook.js
  ```

- Clicked button in app → Frida output:
  ```
  [*] Hooked getSecretMessage(): Holberton{C2.domains.are.dangerous}
  ```

---

## 🏁 Flag Retrieved
```
Holberton{C2.domains.are.dangerous}
```

---

## 📚 Conclusion

- Successfully intercepted the native JNI method.
- Used Frida to hook and extract a hidden flag.
- Demonstrates typical dynamic analysis using Frida and Objection on Android apps with native libraries.

---

## ✅ Recommendations

**For Developers**:
- Do not expose sensitive logic in client-side native code.
- Use anti-hooking/anti-debugging protections.
- Implement runtime integrity checks and obfuscation techniques.

---

## 📎 Appendix

- **Hook script (`hook.js`)**
- **APK SHA256 checksum**:
  ```bash
  sha256sum task1_d.apk
  ```
- **Relevant Java decompiled snippet**
- **Frida command output (attached or inline)**

---
