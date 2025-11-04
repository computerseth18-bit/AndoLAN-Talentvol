# AndoLAN — Basisschool Talentvol (Speciaal Onderwijs AnnoNU)

Klaar-om-te-hosten demo met:
- Frontend (index.html) met Talentvol-styling + login (Microsoft/Google knoppen) + profiel + uitloggen
- Backend (Node/Express) met OpenID Connect (Microsoft Entra ID & Google), SQLite users, JWT sessiecookie
- Render.com config en .env voorbeeld

## Snel lokaal starten
```bash
npm install
cp .env.example .env
# pas BASE_URL en JWT_SECRET aan
node server.js
# open in je browser
http://localhost:3000
```
- Testlogin lokaal: `student1 / wachtwoord1` (alleen als je lokale login gebruikt).

## Render.com (gratis tier) — live demo URL
1. Maak een **nieuwe Git-repo** en push deze map (of upload als nieuw repo).
2. Koppel je Git aan **Render.com** → *New Web Service*.
3. **Environment**: Node, regio: *Frankfurt*, plan: *Free*.
4. Build: `npm install` — Start: `node server.js`
5. Zet omgevingsvariabelen (Dashboard → Environment):
   - `BASE_URL` → Render URL, bijv. `https://andolan-demo.onrender.com`
   - `JWT_SECRET` → sterke geheime sleutel
   - `OIDC_MS_*` en `OIDC_GOOGLE_*` → vul je IdP app-gegevens in
6. Deploy; je live link ziet er zo uit:
   - `https://andolan-demo.onrender.com`

## Replit
- Start een Node.js Repl, upload bestanden, zet `.env` variabelen.
- Run `node server.js`. Open de webview-URL (wordt je demo link).

## Belangrijk (veiligheid/infra)
- Gebruik altijd **HTTPS** in productie en zet `secure: true` op de cookie.
- Beperk **CORS** tot jouw domein.
- Gebruik **sterke** `JWT_SECRET` en roteren indien nodig.
- Overweeg migratie naar **PostgreSQL** voor productie en gebruikersbeheer met rollen.

## Aanpassen huisstijl
- In `index.html` bovenaan staan CSS-variabelen:
  - `--brand`, `--brand-dark`, `--accent`, `--bg`
- Logo staat in `/assets/logo.png`.

Succes! ✨
