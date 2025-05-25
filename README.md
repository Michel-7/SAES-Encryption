# Simplified AES (S-AES) Encryption Tool 🔐

This is a Python implementation of **Simplified AES (S-AES)** using **ECB mode**, developed for educational purposes. It supports:

- Encrypting and decrypting normal **text messages**
- Viewing encrypted output in **hexadecimal format**
- Performing **brute-force cryptanalysis** to recover the original message and key

> Built manually without using any cryptographic libraries — all logic is implemented from scratch following the official S-AES structure.

---

## 📦 Features

- 🔒 **Encrypt/Decrypt** plaintext messages using a 16-bit hex key
- 🧠 **Brute-force decrypt** ciphertext using all possible 16-bit keys
- 🧱 Uses **ECB (Electronic Codebook)** mode
- ✅ Handles UTF-8 messages, including punctuation, symbols, and newlines
- 🛠 Designed for learning how AES-like ciphers work

---

## 🚀 Getting Started

### ✅ Requirements
- Python 3.7 or higher
- No external libraries required

### 🔧 Run the Program

```bash
python main.py