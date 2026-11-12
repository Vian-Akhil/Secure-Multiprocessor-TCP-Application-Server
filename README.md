# Secure Multiprocessor TCP Application Server
Design and Implementation of a Secure Multiprocessor TCP Application  Server with Custom Protocol and Session Management.

A secure, multi-client TCP application server built from scratch in **C**, accompanied by a custom **Python** client[cite: 1, 2, 3]. This project implements a custom explicit framing protocol, concurrent process management via Unix `fork()`, built-in authentication, abuse protection mechanisms, and persistent audit logging[cite: 3, 4].

---

## 🚀 Features

* **Custom TCP Protocol:** Explicit framing architecture using payload length headers (`LEN: <n>`) with robust handling for partial `recv()` calls, multiple buffered messages, and oversized payloads (>4096 bytes)[cite: 3].
* **Multiprocessing (`fork`):** Concurrent client handling where the parent process continuously accepts connections and child processes handle individual sessions, complete with `waitpid()` and `SIGCHLD` handling to prevent zombie processes[cite: 3].
* **Authentication & Session Management:** Secure user registration and login utilizing salted password hashing, dynamic session tokens, protected commands, and automated inactivity token expiration[cite: 3].
* **Abuse Protection:** Built-in client rate limiting, brute-force login lockout logic, username validation, and payload overflow rejection[cite: 3, 4].
* **Persistent Audit Logging:** Detailed server-side logging tracking timestamps, client IP/ports, child PIDs, usernames, commands, and execution results[cite: 4].

---

## 🛠️ Tech Stack & Requirements

* **Server:** Implemented in **C**, compiled with `gcc`, and built using a custom `Makefile`[cite: 2].
* **Client:** Implemented in **Python**[cite: 2].
* **Environment:** Designed for Linux/Unix-based environments.

---