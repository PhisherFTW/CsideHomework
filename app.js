var _a;
// app.ts
(_a = document.getElementById('jsForm')) === null || _a === void 0 ? void 0 : _a.addEventListener('submit', function (event) {
    event.preventDefault();
    var jsInput = document.getElementById('jsInput').value;
    var _a = scanJs(jsInput), severity = _a.severity, confidence = _a.confidence, triggeredRules = _a.triggeredRules;
    var resultDiv = document.getElementById('result');
    if (resultDiv) {
        resultDiv.innerHTML = severity > 0
            ? "<p style=\"color: red;\">\u26A0\uFE0F Possible Malicious JavaScript Detected</p>\n               <p>Confidence Level: ".concat(confidence, "%</p>\n               <h3>Triggered Rules:</h3>\n               <ul>").concat(triggeredRules.map(function (rule) { return "<li><strong>".concat(rule.name, ":</strong> ").concat(rule.description, "</li>"); }).join(''), "</ul>")
            : '<p style="color: green;">✅ No Threats Detected</p>';
    }
});
function scanJs(js) {
    var rules = [
        //Script 1 Rules
        {
            name: "Dynamic Script Loading",
            regex: /var\s+url\s*=\s*["']\/\/[^\/]+\.com\/js\?.*["']/gi,
            description: "Detects dynamic script loading from a generic domain."
        },
        {
            name: "Document Write with Script Injection",
            regex: /document\.write\(\s*"<script.*src.*<\/script>"\s*\)/gi,
            description: "Detects document.write with </script/> tag injection."
        },
        {
            name: "Eval or execScript with XMLHttpRequest",
            regex: /XMLHttpReq\.responseText[\s\S]*?if\s*\(\s*window\.execScript\s*\)[\s\S]*?window\.execScript\s*\(\s*text\s*\);[\s\S]*?else[\s\S]*?window\.eval\s*\(\s*text\s*\);/gi,
            description: "Detects eval or execScript usage with XMLHttpRequest response."
        },
        {
            name: "Synchronous XMLHttpRequest",
            regex: /xhr\.open\(\s*"GET",\s*url,\s*false\s*\)/gi,
            description: "Detects synchronous XMLHttpRequest which may indicate poor coding practices or security concerns."
        },
        // Script 2
        {
            name: "Eval with Unescape/Atob",
            regex: /eval\((\s+)?(unescape|atob)\(/gi,
            description: "Detects attempts to execute decoded or unescaped code using eval() with unescape() or atob()."
        },
        {
            name: "Hex-Encoded Strings in Variables",
            regex: /var(\s+)?([a-zA-Z_$])+([a-zA-Z0-9_$]+)?(\s+)?=(\s+)?\[(\s+)?\"\\x[0-9a-fA-F]+/gi,
            description: "Finds variable declarations that assign an array containing hexadecimal-encoded strings, often used in obfuscation."
        },
        {
            name: "Eval Assigned to Variable",
            regex: /var(\s+)?([a-zA-Z_$])+([a-zA-Z0-9_$]+)?(\s+)?=(\s+)?eval;/gi,
            description: "Detects variables being assigned the eval function, which can be used for indirect code execution."
        },
        {
            name: "Base64 Encoding/Decoding",
            regex: /(atob|btoa|;base64|base64,)/gi,
            description: "Identifies base64 encoding/decoding functions or base64-related strings, which may be used for encoded payloads."
        },
        {
            name: "Base64-Encoded Strings",
            regex: /(?:["']([A-Za-z0-9+/]{40,}=*)["'])/g,
            description: "Matches longer base64-encoded strings enclosed in quotes to reduce false positives.",
        },
        {
            name: "Hex-Based Obfuscated Variables",
            regex: /[_$a-zA-Z][$\w]*\(\s*0x[a-fA-F0-9]+\s*\)/g,
            description: "Detects JavaScript function calls that use hex-based obfuscation techniques, common in malware and packed scripts."
        },
        {
            name: "HTML Comment Removal Obfuscation",
            regex: /\.replace\s*\(\s*['"](?:-->|<--)['"]\s*,\s*['"]['"]\s*\)/gi,
            description: "Detects HTML comment removal which is an obfuscation technique."
        },
        //Script 3 Rules
        {
            name: "Hidden iFrame Injection",
            regex: /document\.createElement\s*\(\s*['"]iframe['"]\s*\)|createElement\s*\(\s*['"]iframe['"]\s*\)/gi,
            description: "Detects JavaScript dynamically creating an iframe, which can be used for clickjacking or hidden content injection."
        },
        {
            name: "Hidden Style Manipulation",
            regex: /setAttribute\s*\(\s*['"]style['"]\s*,\s*['"][^'"]*(opacity\s*:\s*0|display\s*:\s*none|position\s*:\s*absolute)[^'"]*['"]\s*\)/gi,
            description: "Detects attempts to hide elements via CSS styles, which is often used to conceal malicious iframes or tracking pixels."
        },
        {
            name: "Suspicious Event Listeners",
            regex: /addEventListener\s*\(\s*['"](turbo:load|page:change|before-cache|turbo:visit|turbolinks:visit)['"]\s*,\s*/gi,
            description: "Detects event listeners attached to lifecycle events, which could be used to maintain persistence in web applications."
        },
        {
            name: "External Requests to Suspicious Domains",
            regex: /https?:\/\/(?!window\.location\.origin)[a-zA-Z0-9.-]+\/[a-zA-Z0-9/_.-]+/gi,
            description: "Detects JavaScript making requests to external domains, which could indicate data exfiltration or malicious script execution."
        },
        {
            name: "Browser Fingerprinting",
            regex: /navigator\.(userAgent|vendor|platform|appVersion)/gi,
            description: "Detects access to browser fingerprinting APIs, which are commonly used for tracking users across sites."
        },
        {
            name: "Persistent Storage Access",
            regex: /(window\.)?(localStorage|sessionStorage)\.setItem/gi,
            description: "Detects attempts to store data persistently, which could be used for tracking or data leakage."
        },
        {
            name: "Suspicious Global Object Modification",
            regex: /window\[['"]?[a-zA-Z0-9_$]+['"]?\]\s*=\s*/gi,
            description: "Detects modifications of global objects, which can be used to override built-in functions for malicious purposes."
        },
        {
            name: "Obfuscated or Minified Code",
            regex: /(\w{30,})|\\x[a-f0-9]{2}|\\u[a-f0-9]{4}/gi,
            description: "Detects obfuscated code patterns such as long variable names, hex-encoded characters, or Unicode escape sequences."
        },
        //Script 4 Rules
        {
            name: "Captures All Keystrokes",
            regex: /window\.addEventListener\("keydown",\s*e\s*=>\s*{[^}]*e\.key[^}]*}/gi,
            description: "Detects key logging behavior by capturing all keystrokes on keydown events."
        },
        {
            name: "Sends Keystrokes to an External Server",
            regex: /window\.addEventListener\("beforeunload",\s*function\s*\(e\)\s*{[^}]*sendData\([^}]*keys[^}]*externURLKeys[^}]*}/gi,
            description: "Detects sending captured keystrokes to an external server before the page unloads."
        },
        {
            name: "Captures and Sends Form Data",
            regex: /document\.addEventListener\("submit",\s*function\s*\(e\)\s*{[^}]*collectFormData\([^}]*sendData\([^}]*externURL[^}]*}/gi,
            description: "Detects interception of form submissions and sending form data to an external server."
        },
        {
            name: "Uses External Domain for Exfiltration",
            regex: /const\s*externURL\s*=\s*["'][^"']*["'];\s*const\s*externURLKeys\s*=\s*["'][^"']*["']/gi,
            description: "Detects the usage of external URLs for data exfiltration."
        },
        // Extra rules xD
        {
            name: "Basic XSS Script Injection",
            regex: /<script>\s*alert\([^)]*\)\s*<\/script>/gi,
            description: "Detects all script alert()script for basic XSS patterns."
        },
    ];
    var triggeredRules = [];
    rules.forEach(function (rule) {
        if (rule.regex.test(js)) {
            triggeredRules.push(rule);
        }
    });
    var severity = triggeredRules.length;
    var confidence = severity === 1 ? 33.3 : severity === 2 ? 66.6 : severity >= 3 ? 100 : 0;
    return { severity: severity, confidence: confidence.toFixed(1), triggeredRules: triggeredRules };
}
// You can compile the TypeScript with:
// npx tsc app.ts
// And then include the resulting app.js file in your HTML.
