# WebCraft AI Security Scanner

A Spring Boot web app for reviewing the security configuration of websites. You add a site, run a scan, and get a report of findings with evidence and an optional AI explanation.

All checks are passive: the scanner reads what a site returns and does not send attack requests. A report without findings does not mean the site is secure, and every report lists what was not checked.

## Features

- **HTTP checks** — security headers, cookie flags, HTTPS redirect, server version disclosure.
- **TLS checks** — certificate validity, trust and hostname, support for TLS 1.0 / 1.1.
- **OWASP ZAP (optional)** — crawls the site's links and analyzes the responses; forms are not submitted.
- **Reports** — findings grouped by rule and severity, in HTML and JSON.
- **AI analysis (optional)** — explains a scan's findings through OpenRouter with read-only tools. It does not confirm vulnerabilities.

## Tech stack

- Java 21, Spring Boot 4.1.2 (Web MVC, Data JPA / Hibernate)
- PostgreSQL, Thymeleaf, Lombok
- Spring AI 2.0 (`@Tool`), models via OpenRouter
- OWASP ZAP 2.17 in Docker (optional)

## Requirements

- JDK 21+
- PostgreSQL 15+
- Docker (only to run OWASP ZAP)

## Run

1. Create the database:

   ```sql
   CREATE DATABASE "Security_Scanner";
   ```

2. Create a local `.env` file in the project root (it is not committed) and set the values:

   ```bash
   cp .env.example .env
   ```

   | Variable | Purpose |
   |---|---|
   | `DB_PASSWORD` | PostgreSQL password (required) |
   | `ZAP_ENABLED` | `true` turns the ZAP scanner on |
   | `ZAP_API_KEY` | ZAP API key: `openssl rand -hex 32` |
   | `SCAN_LOCAL_PORTS` | localhost ports allowed as a scan target |
   | `OPENROUTER_API_KEY` | OpenRouter key for AI analysis |

   Override the database URL and user with `DB_URL` and `DB_USERNAME` if needed.

3. Start the app from the project root (otherwise `.env` is not found):

   ```bash
   ./mvnw spring-boot:run
   ```

   It is available at **http://localhost:2157/**.

   To enable the ZAP scanner, set `ZAP_ENABLED=true` and `ZAP_API_KEY` in `.env`, then start ZAP:

   ```bash
   docker compose up -d
   ```

## Build

```bash
./mvnw clean package
java -jar target/Security_Scanner-0.0.1-SNAPSHOT.jar
```

## Tests

```bash
./mvnw test
```

Tests need a local PostgreSQL. `@SpringBootTest` tests use the local development database.

## Routes

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/projects` | Projects; add a site as an asset here |
| `POST` | `/assets/{id}/scans` | Start a scan of an asset |
| `GET` | `/scans/{id}` | Scan status, tasks, events and findings |
| `GET` | `/scans/{id}/report` | Scan report (HTML) |
| `GET` | `/api/reports/{id}` | Scan report (JSON) |
| `POST` | `/scans/{id}/analysis` | AI analysis of a scan |
| `GET` | `/findings/{id}` | A finding and its evidence |

## Author

**Vadim Harovyuk** — Java Backend Developer.

- About the author: [Java backend developer Vadim Harovyuk](https://webscraft.org/blog/java-backend-rozrobnik-vadim-harovyuk)
- Project blog: [webscraft.org/blog](https://webscraft.org/blog)

## Security note

The scanner performs passive checks only. Run it only against sites you are allowed to test. Network access is restricted to the asset's host and port, and local targets are limited to `localhost` on the ports listed in `SCAN_LOCAL_PORTS`.
