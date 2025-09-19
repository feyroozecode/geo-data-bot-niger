# geo-data-bot-niger

# Documentation Complète du Backend GeoDataBot

## 📋 Table des Matières
1. [Vue d'ensemble](#vue-densemble)
2. [Architecture Générale](#architecture-générale)
3. [Service NLP et Intelligence Artificielle](#service-nlp-et-intelligence-artificielle)
4. [Gestion des Données Géospatiales](#gestion-des-données-géospatiales)
5. [API et Endpoints](#api-et-endpoints)
6. [🔒 Sécurité de l'API](#sécurité-de-lapi)
7. [Algorithmes de Traitement](#algorithmes-de-traitement)
8. [Configuration et Déploiement](#configuration-et-déploiement)
9. [Performances et Monitoring](#performances-et-monitoring)

## 🎯 Vue d'ensemble

GeoDataBot est un système intelligent de traitement de requêtes géospatiales qui utilise des techniques de traitement du langage naturel (NLP) pour comprendre et répondre aux questions sur des données géographiques. Le système est conçu pour être léger, performant et facile à déployer.

### Objectifs Principaux
- Traitement intelligent de requêtes en langage naturel
- Recherche géospatiale rapide et précise
- Interface API REST simple et efficace
- Architecture modulaire et extensible

## 🏗️ Architecture Générale

```
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│      FRONTEND       │    │       BACKEND       │    │       DONNÉES       │
├─────────────────────┤    ├─────────────────────┤    ├─────────────────────┤
│ Interface React     │───▶│ FastAPI Server      │───▶│ Points Géographiques│
│ Client Axios        │    │ Service NLP         │    │ Métadonnées         │
│                     │◀───│ Processeur Requêtes │    │ Index de Recherche  │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘

Flux de données :
1. Utilisateur → Interface React
2. Interface → Client Axios → FastAPI
3. FastAPI → Service NLP → Traitement
4. NLP → Données géospatiales → Résultats
5. Résultats → FastAPI → Client → Interface
```

### Composants Principaux

1. **Serveur FastAPI** (`nlp_motor.py`)
   - Point d'entrée principal
   - Gestion des requêtes HTTP
   - Configuration CORS
   - Middleware de logging

2. **Service NLP** (`simple_nlp.py`)
   - Traitement du langage naturel
   - Analyse sémantique des requêtes
   - Recherche géospatiale intelligente

3. **Données Géospatiales**
   - Base de données intégrée
   - Index de recherche optimisé
   - Métadonnées enrichies

## 🧠 Service NLP et Intelligence Artificielle

### Architecture du Service NLP

```
PIPELINE DE TRAITEMENT NLP :

[Requête Utilisateur] 
        ↓
[Nettoyage du Texte]
        ↓
[Extraction d'Entités]
        ↓
[Détection d'Intention]
        ↓
[Recherche Géospatiale]
        ↓
[Classement des Résultats]
        ↓
[Formatage de la Réponse]
        ↓
[Réponse Structurée]

Exemple :
"écoles à Niamey" → nettoie → extrait ["écoles", "Niamey"] → 
détecte intention "search_schools" → cherche dans données → 
classe par pertinence → formate réponse → JSON structuré
```

### Algorithmes d'Intelligence Artificielle

#### 1. Extraction d'Entités Géographiques

``python
def extract_geographical_entities(query):
    """
    Algorithme d'extraction d'entités géographiques
    - Reconnaissance de villes, quartiers, types de lieux
    - Analyse contextuelle des termes géographiques
    - Normalisation des noms de lieux
    """
```

**Processus détaillé :**

```
EXTRACTION D'ENTITÉS GÉOGRAPHIQUES :

Requête d'entrée
      ↓
Tokenisation (découpage en mots)
      ↓
Analyse des mots-clés
      ↓
   Ville détectée ?
      ↓           ↓
    OUI          NON
      ↓           ↓
Contexte géo  Recherche générale
      ↓           ↓
      └─── → ─────┘
            ↓
Identification du type de lieu
            ↓
Validation des entités
            ↓
Retour des entités extraites

Exemple :
"hôpitaux à Bamako" → ["hôpitaux", "à", "Bamako"] → 
villes:["Bamako"] types:["hôpitaux"] → validation → 
entités:{ville: "bamako", type: "hopitaux"}
```

#### 2. Détection d'Intention

L'algorithme de détection d'intention utilise une approche basée sur des règles :

```
INTENT_PATTERNS = {
    'search_schools': ['école', 'ecole', 'éducation', 'primaire', 'secondaire'],
    'search_hospitals': ['hôpital', 'hopital', 'santé', 'médical', 'clinique'],
    'search_markets': ['marché', 'marche', 'commerce', 'shopping'],
    'search_restaurants': ['restaurant', 'manger', 'nourriture', 'cuisine'],
    'search_hotels': ['hôtel', 'hotel', 'hébergement', 'logement'],
    'search_parks': ['parc', 'jardin', 'espace vert', 'nature']
}
```

#### 3. Algorithme de Recherche Géospatiale

```
ALGORITHME DE RECHERCHE GÉOSPATIALE :

Entités Extraites
       ↓
   Type de recherche ?
       ↓
   ┌─────┬─────┬─────┐
   │     │     │     │
Par ville │ Par type │ Général
   │     │     │     │
   └─────┼─────┼─────┘
         ↓
   Application des filtres
         ↓
   Calcul de pertinence
         ↓
   Tri des résultats
         ↓
   Limitation (max 10)
         ↓
   Retour des données

Exemples de filtrage :
• Par ville : "Niamey" → filtre tous les points de Niamey
• Par type : "écoles" → filtre toutes les écoles
• Général : "éducation" → recherche dans noms et descriptions
```

### Score de Pertinence

L'algorithme de scoring utilise plusieurs facteurs :

```python
def calculate_relevance_score(item, query_terms, city_match):
    score = 0
    
    # Correspondance exacte du nom (+100 points)
    if any(term.lower() in item['name'].lower() for term in query_terms):
        score += 100
    
    # Correspondance de la ville (+50 points)
    if city_match:
        score += 50
    
    # Correspondance de la description (+25 points)
    if any(term.lower() in item.get('description', '').lower() for term in query_terms):
        score += 25
    
    # Correspondance du type (+75 points)
    if any(term.lower() in item.get('type', '').lower() for term in query_terms):
        score += 75
    
    return score
```

## 📊 Gestion des Données Géospatiales

### Structure des Données

```
STRUCTURE DES DONNÉES GÉOSPATIALES :

ENHANCED_GEOSPATIAL_DATA
├── ecoles/
│   ├── niamey → [École 1, École 2, ...]
│   ├── bamako → [École A, École B, ...]
│   └── ...
├── hopitaux/
│   ├── niamey → [Hôpital 1, Hôpital 2, ...]
│   └── ...
├── marches/
├── restaurants/
├── hotels/
└── parcs/

Structure d'un POINT :
{
  "name": "École Primaire Plateau",
  "lat": 13.5116,
  "lng": 2.1254,
  "type": "École Primaire",
  "description": "École du quartier Plateau",
  "quartier": "Plateau",
  "capacite": 300
}
```

### Catégories de Données Disponibles
857
1. **Écoles** - Établissements éducatifs
2. **Hôpitaux** - Structures de santé
3. **Marchés** - Centres commerciaux
4. **Restaurants** - Établissements de restauration
5. **Hôtels** - Hébergements
6. **Parcs** - Espaces verts et de loisirs

### Villes Couvertes

- **Niamey** (Niger) - 2,000+ points
- **Dosso** (Niger) - 1,000+ points


### Format des Données

```json
{
  "ecoles": {
    "niamey": [
      {
        "name": "École Primaire Plateau",
        "lat": 13.5116,
        "lng": 2.1254,
        "type": "École Primaire",
        "description": "École primaire du quartier Plateau",
        "quartier": "Plateau",
        "capacite": 300,
        "niveau": "Primaire"
      }
    ]
  }
}
```

## 🔌 API et Endpoints

### Endpoint Principal : `/api/chat`

```
FLUX D'UNE REQUÊTE API :

Client                 API                 NLP               Données
  │                     │                   │                   │
  │ POST /api/chat      │                   │                   │
  │ {"message": "..."} │                   │                   │
  ├────────────────────▶│                   │                   │
  │                     │ process_query()   │                   │
  │                     ├──────────────────▶│                   │
  │                     │                   │ search_data()     │
  │                     │                   ├──────────────────▶│
  │                     │                   │ filtered_results  │
  │                     │                   │◀──────────────────┤
  │                     │                   │ calculate_score() │
  │                     │                   │ format_response() │
  │                     │ structured_response│                   │
  │                     │◀──────────────────┤                   │
  │ JSON response       │                   │                   │
  │◀────────────────────┤                   │                   │
  │                     │                   │                   │

Temps de traitement typique : 50-100ms
```

### Structure de la Réponse

```json
{
  "response": "J'ai trouvé 15 écoles à Niamey. Voici les principales:",
  "data": [
    {
      "name": "École Primaire Plateau",
      "lat": 13.5116,
      "lng": 2.1254,
      "type": "École Primaire",
      "description": "École primaire du quartier Plateau"
    }
  ],
  "metadata": {
    "total_found": 15,
    "city": "niamey",
    "category": "ecoles",
    "processing_time": "0.045s"
  }
}
```

### Gestion des Erreurs

```
GESTION DES ERREURS :

Requête
   ↓
Validation ?
   ↓     ↓
 VALID  INVALID
   ↓     ↓
   │   Erreur 400
   │   "Requête invalide"
   ↓
Traitement NLP
   ↓     ↓
   │   Erreur interne ?
   │     ↓
   │   Erreur 500
   │   "Erreur serveur"
   ↓
Résultats trouvés ?
   ↓     ↓
 OUI    NON
   ↓     ↓
Format  Réponse vide
   ↓     "Aucun résultat"
 Succès 200

Codes de retour :
• 200 : Succès avec/sans résultats
• 400 : Requête malformée
• 500 : Erreur serveur interne
```

## 🔒 Sécurité de l'API

### Vue d'ensemble de la Sécurité

La sécurité de l'API GeoDataBot est implementée selon une approche de défense en profondeur, avec plusieurs couches de protection pour garantir l'intégrité, la confidentialité et la disponibilité du service.

```
COUCHES DE SÉCURITÉ :

┌─────────────────────────────────────┐
│        COUCHE RÉSEAU                │
│  • HTTPS/TLS obligatoire            │
│  • Firewall et filtrage IP          │
│  • Protection DDoS                  │
└─────────────────┬───────────────────┘
                  ↓
┌─────────────────────────────────────┐
│      COUCHE APPLICATION             │
│  • Validation des entrées           │
│  • Limitation de débit (Rate limit) │
│  • Headers sécurisés                │
└─────────────────┬───────────────────┘
                  ↓
┌─────────────────────────────────────┐
│       COUCHE DONNÉES                │
│  • Sanitisation des requêtes        │
│  • Validation des données           │
│  • Logs sécurisés                   │
└─────────────────────────────────────┘
```

### 1. Sécurité du Transport

#### Configuration HTTPS/TLS

```python
# Configuration SSL/TLS recommandée
SSL_CONFIG = {
    "protocol": "TLSv1.3",
    "ciphers": "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256",
    "verify_mode": "CERT_REQUIRED",
    "check_hostname": True
}

# Headers de sécurité obligatoires
SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Content-Security-Policy": "default-src 'self'",
    "Referrer-Policy": "strict-origin-when-cross-origin"
}
```

#### Middleware de Sécurité

```python
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    
    # Ajout des headers de sécurité
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    
    # Suppression des headers sensibles
    response.headers.pop("Server", None)
    response.headers.pop("X-Powered-By", None)
    
    return response
```

### 2. Validation et Sanitisation des Entrées

#### Validation des Requêtes

```python
from pydantic import BaseModel, validator, Field
from typing import Optional
import re

class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=500)
    
    @validator('message')
    def validate_message(cls, v):
        # Vérification des caractères dangereux
        dangerous_patterns = [
            r'<script.*?>.*?</script>',  # XSS
            r'javascript:',              # JavaScript injection
            r'data:.*base64',           # Data URI
            r'eval\(',                  # Code execution
            r'exec\(',                  # Code execution
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                raise ValueError("Contenu potentiellement dangereux détecté")
        
        # Nettoyage basique
        v = v.strip()
        v = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', v)
        
        return v
```

#### Sanitisation Avancée

```python
import html
import urllib.parse

def sanitize_input(text: str) -> str:
    """
    Sanitise les entrées utilisateur contre les attaques communes
    """
    # Échappement HTML
    text = html.escape(text)
    
    # Décodage URL sécurisé
    text = urllib.parse.unquote(text)
    
    # Suppression des caractères de contrôle
    text = ''.join(char for char in text if ord(char) >= 32)
    
    # Limitation de la taille
    text = text[:500]
    
    return text

def detect_injection_attempt(text: str) -> bool:
    """
    Détecte les tentatives d'injection SQL/NoSQL/Script
    """
    injection_patterns = [
        # Injection SQL
        r'\b(union|select|insert|update|delete|drop|create|alter)\b',
        r'[\'\"]\s*(or|and)\s*[\'\"]',
        r'\b1\s*=\s*1\b',
        
        # Injection de commandes
        r'[;&|`$(){}\[\]]',
        r'\b(cat|ls|pwd|whoami|id|uname|ps|netstat)\b',
        
        # Injection de scripts
        r'<\s*(script|iframe|object|embed)',
        r'javascript\s*:',
        r'on\w+\s*=',
    ]
    
    for pattern in injection_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    
    return False
```

### 3. Limitation de Débit (Rate Limiting)

#### Configuration Rate Limiting

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Configuration du limiteur
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Limites par endpoint
RATE_LIMITS = {
    "/api/chat": "30/minute",    # 30 requêtes par minute
    "/api/health": "100/minute", # 100 requêtes par minute
    "/api/*": "50/minute"        # Limite générale
}

@app.post("/api/chat")
@limiter.limit("30/minute")
async def chat_endpoint(request: Request, chat_request: ChatRequest):
    # Logique de l'endpoint
    pass
```

#### Rate Limiting Avancé

```python
class AdvancedRateLimiter:
    def __init__(self):
        self.requests = {}  # IP -> liste des timestamps
        self.blocked_ips = {}  # IP -> timestamp de déblocage
    
    def is_rate_limited(self, ip: str, limit: int = 30, window: int = 60) -> bool:
        now = time.time()
        
        # Vérifier si IP est bloquée
        if ip in self.blocked_ips:
            if now < self.blocked_ips[ip]:
                return True
            else:
                del self.blocked_ips[ip]
        
        # Nettoyer les anciennes requêtes
        if ip in self.requests:
            self.requests[ip] = [req for req in self.requests[ip] 
                               if now - req < window]
        else:
            self.requests[ip] = []
        
        # Vérifier la limite
        if len(self.requests[ip]) >= limit:
            # Bloquer l'IP pour 5 minutes
            self.blocked_ips[ip] = now + 300
            return True
        
        # Enregistrer la requête
        self.requests[ip].append(now)
        return False
```

### 4. Authentification et Autorisation

#### Système d'API Keys (Optionnel)

```python
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta

class APIKeyManager:
    def __init__(self):
        self.valid_keys = {}  # key_hash -> {created, expires, permissions}
    
    def generate_api_key(self, permissions: list = None) -> str:
        """
        Génère une nouvelle clé API sécurisée
        """
        key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        
        self.valid_keys[key_hash] = {
            "created": datetime.now(),
            "expires": datetime.now() + timedelta(days=30),
            "permissions": permissions or ["read"],
            "requests_count": 0
        }
        
        return key
    
    def validate_api_key(self, key: str) -> dict:
        """
        Valide une clé API
        """
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        
        if key_hash not in self.valid_keys:
            return {"valid": False, "reason": "Clé invalide"}
        
        key_info = self.valid_keys[key_hash]
        
        if datetime.now() > key_info["expires"]:
            return {"valid": False, "reason": "Clé expirée"}
        
        # Incrémenter le compteur d'utilisation
        key_info["requests_count"] += 1
        
        return {
            "valid": True, 
            "permissions": key_info["permissions"],
            "usage_count": key_info["requests_count"]
        }

# Middleware d'authentification
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    # Exemption pour les endpoints publics
    if request.url.path in ["/health", "/docs", "/openapi.json"]:
        return await call_next(request)
    
    # Vérification de la clé API
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        return JSONResponse(
            status_code=401,
            content={"error": "Clé API requise"}
        )
    
    validation_result = api_key_manager.validate_api_key(api_key)
    if not validation_result["valid"]:
        return JSONResponse(
            status_code=401,
            content={"error": validation_result["reason"]}
        )
    
    # Ajouter les informations d'auth à la requête
    request.state.auth = validation_result
    
    return await call_next(request)
```

### 5. Logging et Monitoring Sécurisés

#### Configuration des Logs Sécurisés

```python
import logging
from logging.handlers import RotatingFileHandler
import hashlib

class SecureLogger:
    def __init__(self):
        # Configuration du logger principal
        self.logger = logging.getLogger("geodatabot_security")
        self.logger.setLevel(logging.INFO)
        
        # Handler pour les logs de sécurité
        security_handler = RotatingFileHandler(
            "security.log", maxBytes=10*1024*1024, backupCount=5
        )
        security_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        security_handler.setFormatter(security_formatter)
        self.logger.addHandler(security_handler)
    
    def log_security_event(self, event_type: str, ip: str, details: dict):
        """
        Enregistre un événement de sécurité
        """
        # Hacher l'IP pour la confidentialité
        ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]
        
        event = {
            "type": event_type,
            "ip_hash": ip_hash,
            "timestamp": datetime.now().isoformat(),
            "details": details
        }
        
        self.logger.warning(f"SECURITY_EVENT: {event}")
    
    def log_suspicious_activity(self, ip: str, reason: str, request_data: dict):
        """
        Enregistre une activité suspecte
        """
        self.log_security_event("SUSPICIOUS_ACTIVITY", ip, {
            "reason": reason,
            "request_path": request_data.get("path"),
            "user_agent": request_data.get("user_agent", "")[:100],
            "request_size": len(str(request_data))
        })

# Utilisation dans l'application
security_logger = SecureLogger()

@app.middleware("http")
async def security_logging_middleware(request: Request, call_next):
    start_time = time.time()
    
    # Collecter les informations de la requête
    request_info = {
        "method": request.method,
        "path": str(request.url.path),
        "user_agent": request.headers.get("user-agent", ""),
        "content_length": request.headers.get("content-length", 0)
    }
    
    # Vérifications de sécurité
    client_ip = request.client.host
    
    # Détection d'activités suspectes
    if detect_suspicious_request(request):
        security_logger.log_suspicious_activity(
            client_ip, "Pattern d'attaque détecté", request_info
        )
    
    response = await call_next(request)
    
    # Logger les erreurs de sécurité
    if response.status_code in [401, 403, 429]:
        security_logger.log_security_event("ACCESS_DENIED", client_ip, {
            "status_code": response.status_code,
            "path": request_info["path"]
        })
    
    return response

def detect_suspicious_request(request: Request) -> bool:
    """
    Détecte les requêtes suspectes
    """
    suspicious_patterns = [
        # User agents suspects
        r'(sqlmap|nikto|nmap|masscan)',
        # Paths suspects
        r'(\.\./|/etc/passwd|/proc/)',
        # Headers suspects
        r'(\${|\<\?php|javascript:)'
    ]
    
    user_agent = request.headers.get("user-agent", "")
    path = str(request.url.path)
    
    for pattern in suspicious_patterns:
        if re.search(pattern, user_agent + path, re.IGNORECASE):
            return True
    
    return False
```

### 6. Protection Contre les Attaques Communes

#### Protection Anti-DDoS

```python
class DDoSProtection:
    def __init__(self):
        self.request_counts = {}  # IP -> compteur
        self.blocked_ips = set()
        self.whitelist = {"127.0.0.1", "::1"}  # IPs de confiance
    
    def check_request(self, ip: str) -> bool:
        """
        Vérifie si la requête doit être autorisée
        """
        if ip in self.whitelist:
            return True
        
        if ip in self.blocked_ips:
            return False
        
        # Compter les requêtes par minute
        now = time.time()
        minute_key = int(now // 60)
        request_key = f"{ip}:{minute_key}"
        
        if request_key not in self.request_counts:
            self.request_counts[request_key] = 0
        
        self.request_counts[request_key] += 1
        
        # Bloquer si trop de requêtes
        if self.request_counts[request_key] > 100:  # 100 req/min max
            self.blocked_ips.add(ip)
            # Débloquer après 10 minutes
            threading.Timer(600, lambda: self.blocked_ips.discard(ip)).start()
            return False
        
        return True

# Protection CSRF
def generate_csrf_token() -> str:
    """Génère un token CSRF sécurisé"""
    return secrets.token_urlsafe(32)

def validate_csrf_token(token: str, expected: str) -> bool:
    """Valide un token CSRF de manière sécurisée"""
    return hmac.compare_digest(token, expected)
```

### 7. Configuration de Production Sécurisée

#### Variables d'Environnement Sécurisées

```python
# .env.production
SECRET_KEY=your-super-secret-key-here-256-bits
API_KEY_SECRET=another-secret-for-api-keys
DATABASE_ENCRYPTION_KEY=database-encryption-key
ALLOWED_HOSTS=your-domain.com,api.your-domain.com
DEBUG=False
SSL_REQUIRED=True
CSRF_PROTECTION=True
RATE_LIMIT_ENABLED=True
LOGGING_LEVEL=WARNING

# Configuration sécurisée
class SecurityConfig:
    SECRET_KEY = os.getenv("SECRET_KEY")
    API_KEY_SECRET = os.getenv("API_KEY_SECRET")
    ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "").split(",")
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"
    SSL_REQUIRED = os.getenv("SSL_REQUIRED", "True").lower() == "true"
    
    @classmethod
    def validate(cls):
        """Valide la configuration de sécurité"""
        if not cls.SECRET_KEY or len(cls.SECRET_KEY) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")
        
        if cls.DEBUG and cls.SSL_REQUIRED:
            logging.warning("DEBUG mode enabled with SSL_REQUIRED")
```

### 8. Tests de Sécurité Automatisés

```python
import pytest
import requests

class TestAPISecurity:
    def test_sql_injection_protection(self):
        """Test protection contre l'injection SQL"""
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "admin'/**/OR/**/1=1--",
            "1' UNION SELECT * FROM users--"
        ]
        
        for payload in malicious_inputs:
            response = requests.post("/api/chat", 
                json={"message": payload})
            assert response.status_code == 400  # Requête rejetée
    
    def test_xss_protection(self):
        """Test protection contre XSS"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<iframe src='javascript:alert(1)'></iframe>"
        ]
        
        for payload in xss_payloads:
            response = requests.post("/api/chat", 
                json={"message": payload})
            assert "<script>" not in response.text
    
    def test_rate_limiting(self):
        """Test de la limitation de débit"""
        # Envoyer plus de requêtes que la limite
        for i in range(35):  # Limite: 30/minute
            response = requests.post("/api/chat", 
                json={"message": f"test {i}"})
        
        # Les dernières requêtes doivent être limitées
        assert response.status_code == 429
    
    def test_security_headers(self):
        """Test présence des headers de sécurité"""
        response = requests.get("/api/health")
        
        required_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security"
        ]
        
        for header in required_headers:
            assert header in response.headers
```

### 9. Plan de Réponse aux Incidents

```
PLAN DE RÉPONSE AUX INCIDENTS DE SÉCURITÉ :

┌─────────────────────┐
│   DÉTECTION         │
│ • Logs d'alerte     │
│ • Monitoring        │
│ • Rapports users    │
└──────────┬──────────┘
           │
           ↓
┌─────────────────────┐
│   ÉVALUATION        │
│ • Criticité         │
│ • Impact            │
│ • Scope             │
└──────────┬──────────┘
           │
           ↓
┌─────────────────────┐
│   CONFINEMENT       │
│ • Isolement système │
│ • Blocage IP        │
│ • Arrêt service     │
└──────────┬──────────┘
           │
           ↓
┌─────────────────────┐
│   INVESTIGATION     │
│ • Analyse logs      │
│ • Forensic          │
│ • Root cause        │
└──────────┬──────────┘
           │
           ↓
┌─────────────────────┐
│   RÉCUPÉRATION      │
│ • Patch sécurité    │
│ • Restoration       │
│ • Tests             │
└──────────┬──────────┘
           │
           ↓
┌─────────────────────┐
│   POST-INCIDENT     │
│ • Rapport détaillé  │
│ • Amélioration      │
│ • Formation         │
└─────────────────────┘

Niveaux de Criticité :
• CRITIQUE : Arrêt immédiat du service
• ÉLEVÉ : Restriction d'accès, surveillance renforcée
• MOYEN : Alertes, investigation approfondie
• FAIBLE : Logging, surveillance continue
```

### 10. Bonnes Pratiques de Sécurité

#### Checklist de Sécurité

```
✅ CHECKLIST SÉCURITÉ API :

📋 TRANSPORT
  □ HTTPS/TLS 1.3 activé
  □ Certificats valides et à jour
  □ Headers de sécurité configurés
  □ HSTS activé

📋 AUTHENTIFICATION
  □ API Keys sécurisées (si applicable)
  □ Tokens avec expiration
  □ Validation des permissions
  □ Logs d'authentification

📋 VALIDATION
  □ Validation stricte des entrées
  □ Sanitisation des données
  □ Protection XSS/injection
  □ Limites de taille des requêtes

📋 LIMITATION
  □ Rate limiting configuré
  □ Protection DDoS active
  □ Timeouts appropriés
  □ Limitation des ressources

📋 MONITORING
  □ Logs sécurisés activés
  □ Alertes temps réel
  □ Métriques de sécurité
  □ Dashboard de monitoring

📋 INFRASTRUCTURE
  □ Firewall configuré
  □ VPN/accès restreint
  □ Sauvegardes sécurisées
  □ Plan de récupération
```

#### Recommandations de Déploiement

```python
# Configuration de production sécurisée
class ProductionSecurityConfig:
    # Serveur
    DEBUG = False
    TESTING = False
    
    # Sécurité réseau
    ALLOWED_HOSTS = ['api.yourdomain.com']
    CORS_ORIGINS = ['https://yourdomain.com']
    
    # SSL/TLS
    FORCE_HTTPS = True
    SSL_REDIRECT = True
    SECURE_HEADERS = True
    
    # Rate limiting
    RATE_LIMIT_ENABLED = True
    RATE_LIMIT_STORAGE = 'redis://localhost:6379'
    
    # Logging
    LOG_LEVEL = 'WARNING'
    SECURITY_LOG_ENABLED = True
    
    # Monitoring
    METRICS_ENABLED = True
    HEALTH_CHECK_ENABLED = True
```

### 11. Audit et Conformité

#### Tests de Pénétration Automatisés

```bash
#!/bin/bash
# Script d'audit sécurité automatisé

echo "🔍 Audit sécurité GeoDataBot API"
echo "================================"

# Test SSL/TLS
echo "📋 Test SSL/TLS..."
sslyze --regular api.yourdomain.com:443

# Test headers sécurité
echo "📋 Test headers sécurité..."
curl -I https://api.yourdomain.com/api/health

# Test rate limiting
echo "📋 Test rate limiting..."
for i in {1..35}; do
  curl -s -w "%{http_code}\n" -o /dev/null \
    https://api.yourdomain.com/api/chat \
    -H "Content-Type: application/json" \
    -d '{"message":"test"}'
done

# Test injection SQL
echo "📋 Test injection SQL..."
malicious_payloads=(
  "'; DROP TABLE users; --"
  "' OR '1'='1"
  "admin'/**/OR/**/1=1--"
)

for payload in "${malicious_payloads[@]}"; do
  curl -X POST https://api.yourdomain.com/api/chat \
    -H "Content-Type: application/json" \
    -d "{\"message\":\"$payload\"}"
done

echo "✅ Audit terminé"
```

---

**🔒 IMPORTANT:** Cette section sécurité doit être régulièrement mise à jour selon les évolutions des menaces et les bonnes pratiques de l'industrie. Un audit de sécurité professionnel est recommandé avant la mise en production.
    def __init__(self):
        self.request_counts = {}  # IP -> compteur
        self.blocked_ips = set()
        self.whitelist = {"127.0.0.1", "::1"}  # IPs de confiance
    
    def check_request(self, ip: str) -> bool:
        """
        Vérifie si la requête doit être autorisée
        """
        if ip in self.whitelist:
            return True
        
        if ip in self.blocked_ips:
            return False
        
        # Compter les requêtes par minute
        now = time.time()
        minute_key = int(now // 60)
        request_key = f"{ip}:{minute_key}"
        
        if request_key not in self.request_counts:
            self.request_counts[request_key] = 0
        
        self.request_counts[request_key] += 1
        
        # Bloquer si trop de requêtes
        if self.request_counts[request_key] > 100:  # 100 req/min max
            self.blocked_ips.add(ip)
            # Débloquer après 10 minutes
            threading.Timer(600, lambda: self.blocked_ips.discard(ip)).start()
            return False
        
        return True

# Protection CSRF
def generate_csrf_token() -> str:
    """Génère un token CSRF sécurisé"""
    return secrets.token_urlsafe(32)

def validate_csrf_token(token: str, expected: str) -> bool:
    """Valide un token CSRF de manière sécurisée"""
    return hmac.compare_digest(token, expected)
```

### 7. Configuration de Production Sécurisée

#### Variables d'Environnement Sécurisées

```python
# .env.production
SECRET_KEY=your-super-secret-key-here-256-bits
API_KEY_SECRET=another-secret-for-api-keys
DATABASE_ENCRYPTION_KEY=database-encryption-key
ALLOWED_HOSTS=your-domain.com,api.your-domain.com
DEBUG=False
SSL_REQUIRED=True
CSRF_PROTECTION=True
RATE_LIMIT_ENABLED=True
LOGGING_LEVEL=WARNING

# Configuration sécurisée
class SecurityConfig:
    SECRET_KEY = os.getenv("SECRET_KEY")
    API_KEY_SECRET = os.getenv("API_KEY_SECRET")
    ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "").split(",")
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"
    SSL_REQUIRED = os.getenv("SSL_REQUIRED", "True").lower() == "true"
    
    @classmethod
    def validate(cls):
        """Valide la configuration de sécurité"""
        if not cls.SECRET_KEY or len(cls.SECRET_KEY) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")
        
        if cls.DEBUG and cls.SSL_REQUIRED:
            logging.warning("DEBUG mode enabled with SSL_REQUIRED")
```

### 8. Tests de Sécurité Automatisés

```python
import pytest
import requests

class TestAPISecurity:
    def test_sql_injection_protection(self):
        """Test protection contre l'injection SQL"""
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "admin'/**/OR/**/1=1--",
            "1' UNION SELECT * FROM users--"
        ]
        
        for payload in malicious_inputs:
            response = requests.post("/api/chat", 
                json={"message": payload})
            assert response.status_code == 400  # Requête rejetée
    
    def test_xss_protection(self):
        """Test protection contre XSS"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<iframe src='javascript:alert(1)'></iframe>"
        ]
        
        for payload in xss_payloads:
            response = requests.post("/api/chat", 
                json={"message": payload})
            assert "<script>" not in response.text
    
    def test_rate_limiting(self):
        """Test de la limitation de débit"""
        # Envoyer plus de requêtes que la limite
        for i in range(35):  # Limite: 30/minute
            response = requests.post("/api/chat", 
                json={"message": f"test {i}"})
        
        # Les dernières requêtes doivent être limitées
        assert response.status_code == 429
    
    def test_security_headers(self):
        """Test présence des headers de sécurité"""
        response = requests.get("/api/health")
        
        required_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security"
        ]
        
        for header in required_headers:
            assert header in response.headers
```

### 9. Plan de Réponse aux Incidents

```
PLAN DE RÉPONSE AUX INCIDENTS DE SÉCURITÉ :

┌─────────────────────┐
│   DÉTECTION         │
│ • Logs d'alerte     │
│ • Monitoring        │
│ • Rapports users    │
└──────────┬──────────┘
           │
           ↓
┌─────────────────────┐
│   ÉVALUATION        │
│ • Criticité         │
│ • Impact            │
│ • Scope             │
└──────────┬──────────┘
           │
           ↓
┌─────────────────────┐
│

### 1. Algorithme de Nettoyage du Texte

``python
def clean_and_normalize_text(text):
    """
    Normalise le texte d'entrée pour améliorer la recherche
    """
    # Conversion en minuscules
    text = text.lower()
    
    # Suppression des accents
    text = unidecode(text)
    
    # Suppression de la ponctuation
    text = re.sub(r'[^\w\s]', ' ', text)
    
    # Normalisation des espaces
    text = ' '.join(text.split())
    
    return text
```

### 2. Algorithme de Correspondance Floue

```
CORRESPONDANCE FLOUE :

Terme de recherche → Normalisation → Génération variantes
                                            ↓
                      Rejeter ← NON ← Correspondance ? ← Calcul distance
                                            ↓             ↓
                                          OUI → Seuil similarité
                                            ↓
                                        Accepter

Exemples :
• "ecole" → "école" (suppression accent)
• "hopital" → "hôpital" (normalisation)
• "maternité" → "maternite" (flexibilité)
• "universite" → "université" (ajout accent)

Seuil de similarité : 80%
```

### 3. Algorithme de Géolocalisation

```python
def calculate_distance(lat1, lng1, lat2, lng2):
    """
    Calcule la distance entre deux points géographiques
    Utilise la formule de Haversine
    """
    R = 6371  # Rayon de la Terre en km
    
    dlat = math.radians(lat2 - lat1)
    dlng = math.radians(lng2 - lng1)
    
    a = (math.sin(dlat/2)**2 + 
         math.cos(math.radians(lat1)) * 
         math.cos(math.radians(lat2)) * 
         math.sin(dlng/2)**2)
    
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    distance = R * c
    
    return distance
```

## 🚀 Configuration et Déploiement

### Variables d'Environnement

```bash
# Configuration du serveur
PORT=8000
HOST=0.0.0.0
DEBUG=True

# Configuration CORS
CORS_ORIGINS=["http://localhost:3000", "http://127.0.0.1:3000"]

# Configuration du logging
LOG_LEVEL=INFO
LOG_FORMAT=detailed
```

### Scripts de Lancement

#### `launch.sh` - Lancement Complet
```bash
#!/bin/bash
# Lance le backend puis le frontend
# Expose tous les ports sur toutes les interfaces
# Surveillance automatique des processus
```

#### `start.sh` - Démarrage Rapide
```bash
#!/bin/bash
# Démarrage rapide du backend uniquement
# Pour le développement et les tests
```

### Architecture de Déploiement

```
ARCHITECTURE DE DÉPLOIEMENT :

┌─────────────────────┐
│    LOAD BALANCER     │ ←── Point d'entrée
└─────────┬───────────┘
          │
    ┌─────┼─────┐
    │     │     │
    ↓     ↓     ↓
┌───────┐ ┌───────┐ ┌───────┐
│Backend1│ │Backend2│ │Backend3│
│ :8000  │ │ :8001  │ │ :8002  │
└───────┘ └───────┘ └───────┘
    │       │       │
    └───────┼───────┘
            │
┌─────────────────────┐
│    FRONTEND :3000    │
└─────────────────────┘

┌─────────────────────┐
│      MONITORING      │
├─────────────────────┤
│ Logs               │
│ Métriques           │
│ Health Checks      │
└─────────────────────┘
```

## 📈 Performances et Monitoring

### Métriques de Performance

```
MÉTRIQUES DE PERFORMANCE :

┌───────────────────────────────────────┐
│              MÉTRIQUES CLÉS                     │
├───────────────────────────────────────┤
│ Response Time       < 100ms   (CIBLE)       │
│ Requests/seconde    > 100 req/s (CIBLE)     │
│ Taux d'erreur      < 1%      (CIBLE)       │
│ Usage mémoire      < 512MB   (CIBLE)       │
│ Usage CPU          < 70%     (CIBLE)       │
└───────────────────────────────────────┘

Alertes automatiques si seuils dépassés :
• Response Time > 200ms → Alerte WARNING
• Response Time > 500ms → Alerte CRITICAL
• Taux d'erreur > 5% → Alerte CRITICAL
• CPU > 90% → Alerte WARNING
```

### Optimisations Implémentées

1. **Cache en Mémoire**
   - Mise en cache des résultats fréquents
   - TTL configurable par type de données
   - Invalidation intelligente

2. **Index de Recherche**
   - Index inversé pour la recherche textuelle
   - Index géospatial pour les coordonnées
   - Compression des données

3. **Traitement Asynchrone**
   - Pool de workers pour les requêtes complexes
   - Queue de priorité pour les requêtes urgentes
   - Timeout configurable

### Monitoring et Logs

```python
# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('geodatabot.log'),
        logging.StreamHandler()
    ]
)

# Métriques personnalisées
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    logger.info(f"Request processed in {process_time:.4f}s")
    return response
```

## 🔧 Maintenance et Évolution

### Ajout de Nouvelles Données

```
AJOUT DE NOUVELLES DONNÉES :

Nouvelles Données
       ↓
Validation du Format
  (structure JSON, coordonnées)
       ↓
Nettoyage et Normalisation
  (accents, espaces, types)
       ↓
Intégration dans ENHANCED_GEOSPATIAL_DATA
  (ajout dans la bonne catégorie/ville)
       ↓
Mise à Jour des Index
  (mots-clés, recherche)
       ↓
Tests de Validation
  (recherche, pertinence)
       ↓
Déploiement
  (restart service)

Processus automatisé via script :
./add_data.py --category ecoles --city niamey --file new_schools.json
```

### Extensibilité

Le système est conçu pour être facilement extensible :

1. **Nouveaux Types de Lieux**
   - Ajout dans `INTENT_PATTERNS`
   - Extension de `ENHANCED_GEOSPATIAL_DATA`
   - Mise à jour des algorithmes de scoring

2. **Nouvelles Villes**
   - Ajout de données géospatiales
   - Configuration des métadonnées
   - Tests de couverture

3. **Nouvelles Langues**
   - Extension des patterns de reconnaissance
   - Traduction des réponses
   - Adaptation des algorithmes NLP

---

**Version :** 1.0  
**Dernière mise à jour :** 2025-09-19  
**Maintenu par :** Équipe GeoDataBot
```

## 🔧 Maintenance et Évolution

### Ajout de Nouvelles Données

```
AJOUT DE NOUVELLES DONNÉES :

Nouvelles Données
       ↓
Validation du Format
  (structure JSON, coordonnées)
       ↓
Nettoyage et Normalisation
  (accents, espaces, types)
       ↓
Intégration dans ENHANCED_GEOSPATIAL_DATA
  (ajout dans la bonne catégorie/ville)
       ↓
Mise à Jour des Index
  (mots-clés, recherche)
       ↓
Tests de Validation
  (recherche, pertinence)
       ↓
Déploiement
  (restart service)

Processus automatisé via script :
./add_data.py --category ecoles --city niamey --file new_schools.json
```

### Extensibilité

Le système est conçu pour être facilement extensible :

1. **Nouveaux Types de Lieux**
   - Ajout dans `INTENT_PATTERNS`
   - Extension de `ENHANCED_GEOSPATIAL_DATA`
   - Mise à jour des algorithmes de scoring

2. **Nouvelles Villes**
   - Ajout de données géospatiales
   - Configuration des métadonnées
   - Tests de couverture

3. **Nouvelles Langues**
   - Extension des patterns de reconnaissance
   - Traduction des réponses
   - Adaptation des algorithmes NLP

---

**Version :** 1.0  
**Dernière mise à jour :** 2025-09-19  
**Maintenu par :** Équipe GeoDataBot
