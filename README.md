# Password Manager

A secure, multi-user, encrypted command‑line password manager built with Python, Argon2id, AES‑256‑GCM, and per‑row integrity verification.

This README provides installation instructions, usage basics, features, and project structure.

---

## ⭐ Features

* **Multi-user support** (each user has their own master password and vault)
* **Strong encryption** using AES‑256‑GCM
* **Argon2id** key derivation with unique salts per user
* **Per-row HMAC integrity protection**
* **Single encrypted database file** (no external salt file)
* **Optional website URL field**
* **Clipboard auto-copy** for passwords
* **Full CRUD operations** (add, list, get, update, delete)
* **Strict input validation / secure regexes**

---

## 📦 Requirements

* Python **3.8+**
* The following Python libraries:

  * `cryptography`
  * `argon2-cffi`
  * `pyperclip`

Install dependencies with:

```bash
pip install -r requirements.txt
```

Or manually:

```bash
pip install cryptography argon2-cffi pyperclip
```

---

## 🚀 Installation

1. Clone or download this repository.
2. Install dependencies.
3. Run the program:

```bash
python3 password_manager_multiuser.py
```


## 🔐 Multi-User System

* Each user has a **username** and **master password**.
* Vault data is **isolated per user**.
* Losing your master password means losing access — **there is no recovery**.

---

## 🧭 Usage

After launching the program and logging in, use the following commands:

### Add a new entry

```
add
```

### List saved services

```
list
```

### Retrieve a password (auto-copied to clipboard)

```
get
```

### Update an entry

```
update
```

### Delete an entry

```
delete
```

### Exit

```
exit
```

---

## 🗄 Database

Everything is stored securely in **one encrypted SQLite database file**.
You can back it up simply by copying this file.

---
