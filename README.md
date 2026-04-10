# Zero Trust Architecture — Web Demo Guide

A two-service Python/Flask implementation of Zero Trust Architecture (ZTA) featuring a live admin control centre and a role-based user portal.

---

## Architecture Overview

```
┌─────────────────────────┐      HTTP/REST      ┌─────────────────────────┐
│  CLIENT PORTAL          │ ──────────────────► │  ZTA SERVER             │
│  client_app.py :5001    │                      │  server_app.py :5000    │
│                         │ ◄────────────────── │                         │
│  • Login page           │   JWT + JSON         │  • Auth engine (JWT)    │
│  • Zone dashboard       │                      │  • Risk scoring         │
│  • Access result modal  │                      │  • Zone access control  │
│                         │                      │  • Admin dashboard      │
│  Users open this        │                      │  • Live log stream      │
└─────────────────────────┘                      └─────────────────────────┘
                                                          ▲
                                                          │ admin browser
                                                   http://localhost:5000/admin
```

---

## Quick Start

### 1. Install dependencies

```bash
cd zt_webapp
pip install -r requirements.txt
```

### 2. Start the ZTA Server (Terminal 1)

```bash
python server_app.py
```

Server runs at **http://127.0.0.1:5000**

### 3. Start the Client Portal (Terminal 2)

```bash
python client_app.py
```

Client runs at **http://127.0.0.1:5001**

---

## Demo Walkthrough

### Step 1 — Open Both Interfaces

| Interface | URL | Credentials |
|---|---|---|
| **Admin Dashboard** | http://localhost:5000/admin | password: `admin123` |
| **User Portal** | http://localhost:5001 | see table below |

### Step 2 — Demo Accounts

| Username | Password | Role | Accessible Zones |
|---|---|---|---|
| `alice` | `alice123` | **admin** | All zones |
| `bob` | `bob123` | **user** | Public, Internal |
| `carol` | `carol123` | **finance** | Public, Internal, Finance |
| `dave` | `dave123` | **devops** | Public, Internal, DevOps |
| `eve` | `eve123` | **guest** | Public only |

---

## ZTA Principles — Where to See Them

### 🔒 Least Privilege
Log in as **eve** (guest). She can only see the Public Portal zone. All others show *✗ No Access* before even sending a request. Log in as **carol** (finance) — Finance Vault is accessible, but DevOps Console is not.

### 🔑 Authentication + Authorisation
Every zone click sends a JWT to the server. The server validates:
1. Token signature and expiry
2. Username exists and is not blocked
3. Session is still active (not revoked)
4. Role has the required permission
5. Risk score is below threshold

Watch the **Live Logs** tab in the Admin Dashboard update in real-time.

### 🗂 Micro-Segmentation
Five isolated zones, each with its own permission requirement:

| Zone | Required Permission | Who Has It |
|---|---|---|
| Public Portal | `read` | everyone |
| Internal Reports | `write` | admin, finance, devops, user |
| Finance Vault | `finance_read` | admin, finance only |
| DevOps Console | `devops` | admin, devops only |
| Admin Control Plane | `manage_users` | admin only |

### 🔄 Continuous Verification
Risk is re-calculated on **every** request, not just at login.

**Demo: Trigger a risk block**
1. In the Admin Dashboard → **Users** tab, find **bob**.
2. Drag the **Risk Boost** slider to **50+**.
3. In the Client Portal (logged in as bob), click **Internal Reports**.
4. Access is now **denied** — risk score exceeded 75, even though bob has the permission.
5. Drag the slider back to 0 — access is restored on the next click.

**Demo: Block a user**
1. In Admin → Users, click **BLOCK** on any user.
2. Their active sessions are immediately revoked.
3. In the Client Portal, any zone click returns *Account blocked*.
4. Watch the red `DENY` entry appear instantly in the Live Logs.

**Demo: Change a role**
1. In Admin → Users, change **eve**'s role to `user` via the dropdown.
2. Eve must log out and back in for the new token to reflect the new permissions.
3. She can now access Internal Reports.

---

## Risk Score Breakdown

The score is computed on **every access request**:

| Factor | Low Risk | High Risk |
|---|---|---|
| User role | admin (5 pts) | guest (50 pts) |
| Device trust | registered device (5 pts) | unknown device (40 pts) |
| Time of day | business hours 08–18 (0 pts) | off-hours (+20 pts) |
| Failed logins | 0 recent fails (0 pts) | 3+ fails in 5 min (+36 pts) |
| Zone sensitivity | Public (5 pts) | Admin (45 pts) |
| Admin boost | 0 pts | up to 50 pts (manual) |

**Access is denied if the total score ≥ 75.**

---

## File Structure

```
zt_webapp/
├── server_app.py     # ZTA engine + admin dashboard  (port 5000)
├── client_app.py     # User portal                   (port 5001)
├── requirements.txt  # Python dependencies
└── README.md         # This file
```

---

## API Reference (Server)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/auth/login` | None | Authenticate, receive JWT |
| POST | `/api/auth/logout` | JWT | Invalidate session |
| GET | `/api/zones` | JWT | List zones with access flags |
| GET | `/api/zones/<id>` | JWT | Access a zone (continuous verify) |
| GET | `/admin/` | Admin session | Dashboard UI |
| GET | `/admin/api/logs` | Admin session | Live log stream |
| GET | `/admin/api/sessions` | Admin session | Active sessions |
| POST | `/admin/api/users/<u>/block` | Admin session | Block a user |
| POST | `/admin/api/users/<u>/risk_boost` | Admin session | Inject risk |
| POST | `/admin/api/users/<u>/role` | Admin session | Change role |

---

## Security Notes

> This is a **demonstration** application. For production use:
> - Store the JWT secret in an environment variable, never in source code.
> - Use HTTPS (TLS) for all communication.
> - Replace the in-memory user/session store with a proper database.
> - Use a secrets manager for credentials.
> - Implement refresh-token rotation instead of single long-lived JWTs.
> - Add rate-limiting and account lockout policies.
