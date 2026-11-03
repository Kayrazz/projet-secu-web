
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
[ ] - Réponses HTTP et JSON
[X] - Token CSRF
[ ] - Contrôle anti SSRF
[ ] - Autorisations (rôles et permissions)
[ ] - Contrôle anti Path Traversal
[ ] - Upload sécurisé (taille, type MIME, whitelist…)
[ ] - Templating / filtrage contre le XSS
[ ] - Rate limiting (fenêtre fixe pour simplifier)
[ ] - Logging des éléments qui vous semblent importants
[ ] - Validation des données (entiers, regex…)

Bonus selon temps disponible
Les frameworks implémentent d’autres fonctionnalités qui relèvent plus de l’architecture que de
la sécurité pure, mais dont l’étude est intéressante :
[ ] - ORM
[ ] - Model binding (ex: /users/2 => function(User $user) {})
[ ] - Routes sécurisées (signed routes / magic links)
[ ] - Système de middleware
[ ] - Système de migrations / seeding de la base de données
[ ] - Lecture du .env / variables d’environnements
[ ] - Gestionnaires d’exeptions (que faire lorsqu’une erreur critique se produit ?)
[ ] - Injection de dépendances

# TODO saisie à la mains:
[ ] - Encodages(Contournements)
[ ] - XSS(Stored,reflected,Dom Based)
[ ] - CSRF
[ ] - SSRF
[ ] - SQLI(Boolean, time-based)

[ ] - COOKIES
[ ] - JWT
[ ] - SOP(Same Origin Policy)
[ ] - Clickjacking et headers
[ ] - CSP
[ ] - RBAC
[ ] - IDDR

[ ] - Path Traversal
[ ] - Uploads
[ ] - Rate Limiting
[ ] - Broken Authentication
[ ] - Loys(RGPD/CNIL)

[ ] - Audit et outil CI/CD