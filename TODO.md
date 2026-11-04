
# Fonctionnalités à implémenter
L’objectif est d’implémenter manuellement la plupart des fonctionnalites de sécurité d’un
framework.
[X] - Authentification sécurisée (session, régénération de l’id…)
[X] - Stockage mdp sécurisé (argon2id, bcrypt…)
[X] - Cookies avec des défauts sécurisants
[X] - En-tête HTTP (HSTS)
[X] - En-tête HTTP (CSP)
[X] - En-tête HTTP (Clickjacking)
[X] - En-tête HTTP (MIME Sniffing…)
‣ Dont politique CSP
[X] - Défense contre l’injection SQL (usage de requêtes préparées)
[X] - Réponses HTTP et JSON
[X] - Token CSRF
[X] - Contrôle anti SSRF
[X] - Autorisations (rôles et permissions)
[X] - Contrôle anti Path Traversal
[X] - Upload sécurisé (taille, type MIME, whitelist…)
[X] - Templating / filtrage contre le XSS
[X] - Rate limiting (fenêtre fixe pour simplifier)
[X] - Logging des éléments qui vous semblent importants
[X] - Validation des données (entiers, regex…)

Bonus selon temps disponible
Les frameworks implémentent d’autres fonctionnalités qui relèvent plus de l’architecture que de
la sécurité pure, mais dont l’étude est intéressante :
[ ] - ORM
[ ] - Model binding (ex: /users/2 => function(User $user) {})
[ ] - Routes sécurisées (signed routes / magic links)
[I] - Système de middleware
[ ] - Système de migrations / seeding de la base de données
[X] - Lecture du .env / variables d’environnements
[ ] - Gestionnaires d’exeptions (que faire lorsqu’une erreur critique se produit ?)
[ ] - Injection de dépendances

# TODO saisie à la mains:
[X] - Encodages(Contournements)
[X] - XSS(Stored,reflected,Dom Based)
[X] - CSRF
[X] - SSRF
[X] - SQLI(Boolean, time-based)

[X] - COOKIES
[X] - JWT
[ ] - SOP(Same Origin Policy)
[X] - Clickjacking et headers
[X] - CSP
[ ] - RBAC
[ ] - IDDR

[X] - Path Traversal
[X] - Uploads
[X] - Rate Limiting
[ ] - Broken Authentication
[ ] - Loys(RGPD/CNIL)

[ ] - Audit et outil CI/CD