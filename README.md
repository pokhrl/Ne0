<img width="590" height="278" alt="Screenshot 2026-05-15 172141" src="https://github.com/user-attachments/assets/319ad6ce-1fa8-409a-82c4-a2727e7570f1" />

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Type](https://img.shields.io/badge/Recon-Attack%20Surface-red)

> Lightweight external attack surface intelligence tool for security researchers.

---

## OVERVIEW

Ne0 is a modular reconnaissance framework that automates domain intelligence gathering such as subdomains, DNS records, WHOIS, ports, technologies, and security headers.

Built for speed, structure, and clarity.

---

## FEATURES

- Subdomain enumeration  
- DNS intelligence  
- WHOIS lookup  
- Port scanning  
- Technology fingerprinting  
- WAF detection  
- Email security checks  
- HTTP header analysis  
- JSON / HTML reporting  
- Multi-threaded scanning  

---

## INSTALL

```bash
git clone https://github.com/pokhrl/Ne0.git
cd Ne0
pip install -r requirements.txt

python main.py example.com
python main.py example.com --all
python main.py example.com --all --output html
