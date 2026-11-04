# Atelier // Boutique

Projet e-commerce pédagogique en Node.js natif, sans framework ni dépendance npm. L'application présente une connexion, un JWT signé manuellement dans un cookie HttpOnly, un rate limiting mémoire et une page d'accueil privée vide.

## Prérequis

- Node.js `>= 22.5` (pour `node:sqlite`)

## Lancer le projet

```bash
npm start
```

Puis ouvrir http://localhost:3000/login.

Compte de démonstration : `demo@example.com` / `Demo1234!`

Pour le développement :

```bash
npm run dev
```

Variables utiles : copiez `.env.example` vers `.env` et exportez-les dans votre environnement. `JWT_SECRET` doit être remplacé en production. Le mode broken authentication de démonstration reste désactivé par défaut et peut être activé uniquement dans un environnement de lab avec `ENABLE_BROKEN_AUTH_LAB=true`.

## Architecture

- `src/server.js` : serveur HTTP, routes API, fichiers statiques et headers de sécurité.
- `src/security.js` : hash `scrypt`, JWT HS256, cookies.
- `src/db.js` : initialisation SQLite et requêtes paramétrées.
- `src/rate-limit.js` : limitation des tentatives de connexion par IP.
- `data/schema.sql` : schéma SQL du compte utilisateur.
- `public/app.js` : routing front avec History API et garde d'authentification.
- `src/model-binding.js` : résolution et validation des modèles depuis les paramètres de route.

La route `GET /api/figurines/:id` utilise le model binding : l’identifiant est validé avant
la recherche paramétrée en base, et renvoie `400` pour un identifiant invalide ou `404`
si la figurine n’existe pas.

## Limites assumées

Le rate limiting est local au processus et doit être remplacé par un stockage partagé en production. Le JWT est stateless : une déconnexion supprime le cookie, mais un token déjà copié reste valide jusqu'à son expiration. HTTPS est obligatoire en production pour que le cookie soit marqué `Secure`.