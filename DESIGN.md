# Design: Secure Bio Page API

## Approach and Priorities

This take-home is explicitly not about completeness — it's about demonstrating how I think about security, tradeoffs, and implementation choices. I treated it that way.

**What I prioritized:**

The highest-impact security work is authentication and access control enforcement. A system that leaks or allows unauthorized modification of user data is fundamentally broken regardless of how polished the rest of it is. So I focused on:

1. Getting the auth flow correct end-to-end (signup → JWT → protected routes)
2. Making sure authorization is enforced at the framework level via guards, not scattered in service logic
3. Handling the subtle security details that are easy to miss — timing-safe login, password never in JWT, secure-by-default routing

**What I consciously deferred and why:**

- **Rate limiting** on auth endpoints — meaningful protection, but requires `@nestjs/throttler` wiring. Wanted time on the core access control model first.
- **Refresh tokens / revocation** — JWTs can't be revoked without a token store. For a time-boxed exercise with an in-memory DB, 24h tokens are an acceptable tradeoff.
- **Read-only share tier** — the schema supports it (one column addition), but implementing the guard distinction would have consumed time better spent on the ownership model.
- **Email verification** — not the security focus of this exercise.

---

## 1. System Overview

```mermaid
graph TD
    FE["Frontend\n(Vite + React)\nlocalhost:5173"]
    API["NestJS API\nlocalhost:3000"]
    DB["pg-mem\n(In-Memory DB)"]

    FE -->|"HTTP (dev) / HTTPS (prod)"| API
    API --> DB

    subgraph API["NestJS API"]
        GG["Global JwtAuthGuard"]
        AC["AuthController\nPOST /auth/signup\nPOST /auth/login"]
        BC["BioPagesController\nGET · POST · PATCH\n+ share endpoints"]
        AS["AuthService\nbcrypt · JWT"]
        BS["BioPagesService\nownership · share checks"]
    end
```

---

## 2. Threat Model

### Assets and Threat Actors

```mermaid
graph LR
    subgraph Actors["Threat Actors"]
        A1["Anonymous\nOutsider"]
        A2["Malicious\nAuth User"]
        A3["Semi-trusted\nShared User"]
        A4["Network\nAttacker (MITM)"]
        A5["Automated Bot\n(credential stuffing)"]
    end

    subgraph Assets["Protected Assets"]
        P1[/"User Passwords\n★★★★★"/]
        P2[/"JWT Tokens\n★★★★"/]
        P3[/"owner_user_id binding\n★★★★"/]
        P4[/"Bio Page Content\n★★★"/]
        P5[/"User Emails (PII)\n★★★"/]
        P6[/"Share Relationships\n★★"/]
    end

    A1 -->|"scrape / tamper"| P4
    A1 -->|"enumerate"| P5
    A2 -->|"IDOR attack"| P3
    A2 -->|"brute force"| P1
    A3 -->|"privilege escalation"| P3
    A4 -->|"intercept"| P2
    A5 -->|"credential stuffing"| P1
```

### STRIDE Threat Map

```mermaid
graph TD
    subgraph S["Spoofing"]
        S1["Forge JWT\n→ Weak secret\nMitigation: strong HS256 secret"]
        S2["Login as another user\n→ Weak password\nMitigation: bcrypt cost 12"]
        S3["JWT replay after logout\n→ No revocation\nMitigation: 24h expiry\nDeferred: denylist"]
    end

    subgraph T["Tampering"]
        T1["Edit another's bio page\n→ PATCH without ownership\nMitigation: ownership check in service"]
        T2["Inject owner_user_id via PATCH\n→ Steal ownership\nMitigation: ValidationPipe whitelist strips it"]
        T3["SQL injection via fields\n→ Unsanitized input\nMitigation: replaceQueryArgs$ parameterization"]
    end

    subgraph I["Info Disclosure"]
        I1["Email enumeration on login\n→ Different error messages\nMitigation: identical 401 + timing-safe compare"]
        I2["Share list leakage\n→ Non-owner reads shares\nMitigation: owner-only GET /shares"]
        I3["Password in logs\n→ Unhandled exception\nMitigation: password never returned or logged"]
    end

    subgraph E["Elevation of Privilege"]
        E1["Shared user manages shares\n→ Viral unauthorized access\nMitigation: assertOwner() on all share endpoints"]
        E2["Unauth user creates pages\n→ Spam / resource abuse\nMitigation: JwtAuthGuard blocks 401"]
        E3["Crafted sub claim in JWT\n→ Impersonate any userId\nMitigation: HS256 signature validation"]
    end

    subgraph D["Denial of Service"]
        D1["Credential stuffing /auth/login\n→ High-volume requests\nDeferred: rate limiting"]
        D2["Oversized payload\n→ Memory exhaustion\nMitigation: class-validator Length + ArrayMaxSize"]
    end
```

### Trust Boundaries

```mermaid
graph TD
    NET["Public Internet"]

    NET -->|"All traffic"| TLS["TLS Termination\n(prod)"]
    TLS --> JWT_BOUNDARY

    subgraph JWT_BOUNDARY["Trust Boundary 1 — Authentication"]
        direction LR
        PUB["Public zone\nGET /bio-pages\nGET /bio-pages/:id\nGET /bio-pages/handle/:handle\nPOST /auth/signup\nPOST /auth/login"]
        AUTH["Authenticated zone\nPOST /bio-pages\nPATCH /bio-pages/:id\n/share endpoints"]
    end

    AUTH --> OWNER_BOUNDARY

    subgraph OWNER_BOUNDARY["Trust Boundary 2 — Authorization"]
        direction LR
        OWN["Owner actions\nPATCH own page\nPOST share\nDELETE share\nGET shares"]
        SHARED["Shared-user actions\nPATCH shared page only"]
        DENIED["Denied — 403\nAll other pages"]
    end
```

---

## 3. Authentication Flows

### Signup

```mermaid
sequenceDiagram
    actor Client
    participant AC as AuthController
    participant AS as AuthService
    participant DB as pg-mem

    Client->>AC: POST /auth/signup { email, password }
    AC->>AC: ValidationPipe — IsEmail, MinLength(8)
    AC->>AS: signup(dto)
    AS->>AS: normalize email → lowercase
    AS->>DB: SELECT id FROM users WHERE email = ?
    alt Email already registered
        DB-->>AS: row found
        AS-->>AC: 409 ConflictException
        AC-->>Client: 409 "Email already registered"
    else New user
        DB-->>AS: empty
        AS->>AS: bcrypt.hash(password, cost=12)
        AS->>DB: INSERT INTO users
        AS->>AS: derive handle from email prefix
        AS->>DB: INSERT INTO bio_pages (owner_user_id = userId)
        AS->>AS: jwtService.sign({ sub: userId, email })
        AS-->>AC: { accessToken }
        AC-->>Client: 201 { accessToken }
    end
```

### Login (with timing-safe protection)

```mermaid
sequenceDiagram
    actor Client
    participant AC as AuthController
    participant AS as AuthService
    participant DB as pg-mem

    Client->>AC: POST /auth/login { email, password }
    AC->>AS: login(dto)
    AS->>AS: normalize email → lowercase
    AS->>DB: SELECT * FROM users WHERE email = ?
    DB-->>AS: user row (or empty)

    Note over AS: ALWAYS run bcrypt.compare<br/>regardless of whether user exists.<br/>Uses dummy hash if user not found.<br/>Prevents timing-based email enumeration.

    AS->>AS: bcrypt.compare(password, hash OR dummyHash)

    alt User not found OR hash mismatch
        AS-->>AC: 401 UnauthorizedException
        AC-->>Client: 401 "Invalid credentials"
    else Valid credentials
        AS->>AS: jwtService.sign({ sub: userId, email })
        AS-->>AC: { accessToken }
        AC-->>Client: 200 { accessToken }
    end
```

---

## 4. Authorization Flows

### PATCH /bio-pages/:id — Access Decision

```mermaid
flowchart TD
    A([PATCH /bio-pages/:id]) --> B{JWT present\nand valid?}
    B -- No --> C[401 Unauthorized]
    B -- Yes --> D[Attach req.user\nuserId + email]
    D --> E[Fetch bio page from DB]
    E --> F{Page exists?}
    F -- No --> G[404 Not Found]
    F -- Yes --> H{owner_user_id\n= req.userId?}
    H -- Yes --> I[✅ Allow — owner]
    H -- No --> J{owner_user_id\n= NULL?\nseed page}
    J -- Yes --> K[✅ Allow — legacy\nseed page]
    J -- No --> L{userId in\nbio_page_shares\nfor this page?}
    L -- Yes --> M[✅ Allow — shared user]
    L -- No --> N[403 Forbidden]

    style C fill:#ff6b6b,color:#fff
    style G fill:#ff6b6b,color:#fff
    style N fill:#ff6b6b,color:#fff
    style I fill:#51cf66,color:#fff
    style K fill:#ffd43b,color:#333
    style M fill:#51cf66,color:#fff
```

### Share Grant Flow

```mermaid
sequenceDiagram
    actor Owner
    actor Bob
    participant BC as BioPagesController
    participant BS as BioPagesService
    participant DB as pg-mem

    Owner->>BC: POST /bio-pages/:id/share { email: bob@example.com }
    BC->>BC: JwtAuthGuard — validate token
    BC->>BS: shareWith(pageId, ownerUserId, dto)
    BS->>DB: SELECT bio_page WHERE id = pageId
    BS->>BS: assertOwner — ownerUserId matches?
    alt Not owner
        BS-->>BC: 403 Forbidden
        BC-->>Owner: 403 "Only the page owner can manage shares"
    else Is owner
        BS->>BS: Check self-share (owner email = target email?)
        alt Self-share
            BS-->>BC: 400 Bad Request
            BC-->>Owner: 400 "You cannot share a page with yourself"
        else Different user
            BS->>DB: SELECT users WHERE email = bob@example.com
            alt User not found
                BS-->>BC: 404 Not Found
                BC-->>Owner: 404 "No user found with that email"
            else User found
                BS->>DB: INSERT INTO bio_page_shares (idempotent)
                BS->>DB: SELECT shares JOIN users for this page
                DB-->>BS: [{ shared_with_user_id, email }]
                BS-->>BC: updated share list
                BC-->>Owner: 200 [{ shared_with_user_id, email }]
            end
        end
    end
```

### Share Revoke Flow

```mermaid
sequenceDiagram
    actor Owner
    participant BC as BioPagesController
    participant BS as BioPagesService
    participant DB as pg-mem

    Owner->>BC: DELETE /bio-pages/:id/share/:targetUserId
    BC->>BC: JwtAuthGuard — validate token
    BC->>BS: revokeShare(pageId, ownerUserId, targetUserId)
    BS->>DB: SELECT bio_page WHERE id = pageId
    BS->>BS: assertOwner — ownerUserId matches?
    alt Not owner
        BS-->>BC: 403 Forbidden
        BC-->>Owner: 403 "Only the page owner can manage shares"
    else Is owner
        BS->>DB: DELETE FROM bio_page_shares WHERE bio_page_id = ? AND shared_with_user_id = ?
        BS->>DB: SELECT remaining shares
        DB-->>BS: updated share list
        BS-->>BC: updated share list
        BC-->>Owner: 200 [] (or remaining shares)
    end
```

---

## 5. Database Schema

```mermaid
erDiagram
    users {
        TEXT id PK
        TEXT email UK
        TEXT password_hash
        TEXT created_at
    }

    bio_pages {
        TEXT id PK
        TEXT handle UK
        TEXT display_name
        TEXT bio
        TEXT links_json
        TEXT owner_user_id FK
        TEXT created_at
        TEXT updated_at
    }

    bio_page_shares {
        TEXT bio_page_id PK,FK
        TEXT shared_with_user_id PK,FK
    }

    users ||--o{ bio_pages : "owns"
    bio_pages ||--o{ bio_page_shares : "shared via"
    users ||--o{ bio_page_shares : "shared with"
```

---

## 6. Module Structure

```mermaid
graph TD
    subgraph AppModule
        DM["DatabaseModule\n@Global — single pg-mem instance"]
        AM["AuthModule"]
        BM["BioPagesModule"]
        GG["APP_GUARD → JwtAuthGuard\nprotects all routes by default"]
    end

    subgraph AuthModule
        AC2["AuthController\nPOST /auth/signup\nPOST /auth/login"]
        AS2["AuthService\nsignup · login · bcrypt · JWT"]
        JS["JwtStrategy\nvalidates Bearer token\nattaches req.user"]
        JG["JwtAuthGuard\nreads @Public() metadata"]
        PD["@Public() decorator"]
        JM["JwtModule\nHS256 · 24h expiry"]
        PM["PassportModule"]
    end

    subgraph BioPagesModule
        BC2["BioPagesController\nGET (public) · POST · PATCH\nshare · revoke · list"]
        BS2["BioPagesService\nownership check · share logic"]
        DTO["DTOs\ncreate · update · share"]
    end

    DM -->|"provides DatabaseService globally"| AS2
    DM -->|"provides DatabaseService globally"| BS2
    AM --> AC2
    AM --> AS2
    AM --> JS
    AM --> JG
    AM --> PD
    AM --> JM
    AM --> PM
    BM --> BC2
    BM --> BS2
    BM --> DTO
```

---

## 7. Permission Matrix

```mermaid
graph LR
    subgraph Routes
        R1["GET /bio-pages"]
        R2["GET /bio-pages/:id"]
        R3["GET /bio-pages/handle/:handle"]
        R4["POST /auth/signup\nPOST /auth/login"]
        R5["POST /bio-pages"]
        R6["PATCH /bio-pages/:id"]
        R7["POST /bio-pages/:id/share\nDELETE /bio-pages/:id/share/:uid\nGET /bio-pages/:id/shares"]
    end

    subgraph Principals
        P1["Anonymous"]
        P2["Any Auth User"]
        P3["Shared User"]
        P4["Owner"]
    end

    P1 -->|"✅ allowed"| R1
    P1 -->|"✅ allowed"| R2
    P1 -->|"✅ allowed"| R3
    P1 -->|"✅ allowed"| R4
    P1 -->|"🚫 401"| R5
    P1 -->|"🚫 401"| R6
    P1 -->|"🚫 401"| R7

    P2 -->|"✅ allowed"| R5
    P2 -->|"🚫 403 (others' pages)"| R6
    P2 -->|"🚫 403"| R7

    P3 -->|"✅ allowed"| R6
    P3 -->|"🚫 403"| R7

    P4 -->|"✅ allowed"| R6
    P4 -->|"✅ allowed"| R7
```

---

## 8. Password Security

- **Algorithm:** bcrypt, cost factor 12 (~250ms per hash on modern hardware — slow enough to resist brute force, fast enough for UX)
- **Never stored or logged in plaintext** — hashed immediately in `AuthService`, raw string never persisted or returned
- **Not in JWT payload** — token contains only `userId` and `email`
- **Timing-safe login** — `bcrypt.compare` always runs even when the user does not exist, using a dummy hash. Prevents distinguishing "wrong email" from "wrong password" via response timing

---

## 9. Tradeoffs and Assumptions

### Assumptions

- **One bio page auto-created at signup.** A user can create additional pages via `POST /bio-pages`; there is no hard one-per-user limit beyond the auto-creation.
- **Sharing is edit-sharing only.** Public read is already open; a read-only grant between users adds no value without private pages first.
- **Sharing by email.** Users must know each other's email. Mirrors real collaboration tools; avoids exposing a user directory endpoint.
- **Seed rows are ownerless.** Three seeded pages have `owner_user_id = NULL` and are editable by any authenticated user for demo purposes. In production they would have real owners or be removed.
- **`JWT_SECRET` has a dev fallback.** Must be overridden via environment variable in production. A startup check (`if (!process.env.JWT_SECRET) throw`) would be added with more time.

### Tradeoffs

| Decision | Alternative | Reasoning |
|---|---|---|
| JWT (stateless) | Sessions + Redis | No persistent store — pg-mem is in-memory by design |
| bcrypt cost 12 | Argon2id | bcrypt simpler; Argon2id preferable for new production systems — noted as future work |
| HS256 | RS256 | Single-service app; asymmetric keys add operational complexity with no benefit here |
| Share by email | Share by user ID | More ergonomic; adds one lookup query, worth it |
| Global guard + `@Public()` opt-out | Per-route opt-in | Secure by default — new routes blocked unless explicitly opened |
| 24h expiry, no refresh | Short expiry + refresh tokens | Refresh tokens require a server-side store, contradicts in-memory DB constraint |
| Ownership check in service | Dedicated guard class | Service already fetches the page; co-location avoids a redundant DB query |

---

## 10. What Would Be Added With More Time

```mermaid
graph LR
    subgraph P1_["Priority 1 — High Impact"]
        W1["Rate limiting\n@nestjs/throttler\n5 req/min on /auth/*"]
        W2["JWT revocation\ntoken denylist in persistent store\n+ POST /auth/logout"]
    end

    subgraph P2_["Priority 2 — Security Hardening"]
        W3["Argon2id\nreplace bcrypt\nbetter memory-hardness"]
        W4["RS256\nasymmetric signing\nfor multi-service environments"]
        W5["Required JWT_SECRET\nfail fast at startup\nif env var absent"]
    end

    subgraph P3_["Priority 3 — Feature Completeness"]
        W6["Refresh tokens\n15min access + long-lived refresh"]
        W7["Read-only share tier\npermission column in bio_page_shares"]
        W8["Private bio pages\nvisibility: public or private"]
        W9["Email verification\nconfirm ownership before activation"]
    end

    subgraph P4_["Priority 4 — Observability"]
        W10["Audit log\nupdated_by · share grant/revoke events"]
        W11["Frontend integration\nwire Login button\nJWT in memory not localStorage"]
    end
```

---

## 11. API Error Reference

| Situation | HTTP | Message |
|---|---|---|
| Missing or invalid JWT | 401 | Unauthorized |
| Wrong email or password | 401 | "Invalid credentials" (same for both — by design) |
| Not owner, not shared | 403 | "You do not have permission to edit this bio page" |
| Non-owner accessing shares | 403 | "Only the page owner can manage shares" |
| Resource not found | 404 | "Bio page not found" / "No user found with that email" |
| Handle conflict | 409 | "Handle already exists" |
| Validation failure | 400 | Field-level details from class-validator |
| Self-share | 400 | "You cannot share a page with yourself" |
| Email already registered | 409 | "Email already registered" |
