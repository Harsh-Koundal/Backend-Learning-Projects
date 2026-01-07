# 🔐 Secure Authentication Service (Access & Refresh Token)

A **production-ready authentication backend** built with **Node.js, Express, MongoDB**, implementing **JWT-based authentication** using **short-lived access tokens** and **rotating refresh tokens** stored securely in **HTTP-only cookies**.

This project follows **real-world backend security practices** used in modern applications.

---

## 🚀 Features

- User registration & login
- JWT authentication (Access + Refresh tokens)
- Refresh token rotation (replay attack protection)
- Refresh tokens stored in **HTTP-only cookies**
- Hashed refresh tokens in database
- Secure logout (token invalidation)
- Password hashing using bcrypt
- Role-ready user model (USER / ADMIN)
- Clean & minimal architecture (single auth controller)

---

## 🧠 Authentication Strategy

### 🔑 Access Token
- Short-lived (`15 minutes`)
- Sent via `Authorization: Bearer <token>`
- Used to access protected APIs

### 🔁 Refresh Token
- Long-lived (`7 days`)
- Stored in **HTTP-only cookie**
- Hashed before saving in DB
- Rotated on every refresh

> If the access token expires, the client **automatically calls `/auth/refresh`** to get a new one.

---

## 🏗️ Tech Stack

- **Node.js**
- **Express.js**
- **MongoDB + Mongoose**
- **JWT**
- **bcrypt**
- **cookie-parser**
- **crypto**
- **dotenv**

---
