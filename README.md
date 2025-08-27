Usage:
# WAF Engine

This is a custom Web Application Firewall (WAF) engine designed to analyze incoming HTTP requests before they reach backend services.  
It is built to work in combination with a reverse proxy (e.g., Nginx, Envoy, or a custom Go/Python proxy).

---

## 🚀 Features
- Normalizes and inspects HTTP requests.
- Detects malicious patterns (SQLi, XSS, etc.).
- Returns **allow** or **block** decisions to the reverse proxy.
- Can run as a standalone service (Flask API).

---

## 📦 Installation

Clone this repository:

```bash
git clone --new-concept https://github.com/abesaade27/waf-engine.git
cd waf-engine
```
---
Go to waf.go file and click on run without debugging, running any other file will give launch.json error.

The waf will start running on 127.0.0.1:9000
---
