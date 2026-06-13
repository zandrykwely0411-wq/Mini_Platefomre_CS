// ============================================================
// Application de démonstration en cybersécurité (M2)
// Auteur : RATSIMBAZAFY Miandrisoa Notahinjanahary Emile
// Description : Plateforme interactive avec 5 modules pédagogiques
// ============================================================
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	mrand "math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed static
var staticFiles embed.FS

// ============================================================
// GESTION DES CLÉS AES PAR SESSION (cookie sécurisé)
// ============================================================

// sessionEntry représente une clé de chiffrement associée à une session utilisateur,
// ainsi que la date de dernière utilisation pour un nettoyage automatique.
type sessionEntry struct {
	key      []byte    // clé AES-256 (32 octets)
	lastUsed time.Time // dernier accès à cette session
}

// Stockage des sessions en mémoire (map) avec un mutex pour éviter les accès concurrents.
var (
	sessionStore = map[string]sessionEntry{}
	sessionMu    sync.Mutex
)

// getSessionKey récupère ou crée une clé AES pour la session identifiée par un cookie.
// Elle génère un ID de session si le cookie n'existe pas, puis associe une clé aléatoire.
// La clé est conservée côté serveur et n'est jamais envoyée au client.
func getSessionKey(w http.ResponseWriter, r *http.Request) []byte {
	// Lecture du cookie existant
	cookie, err := r.Cookie("session_id")
	var sessionID string
	if err != nil || cookie.Value == "" {
		// Pas de session : création d'un ID unique (16 octets hexadécimaux)
		b := make([]byte, 16)
		rand.Read(b)
		sessionID = hex.EncodeToString(b)
		// Création du cookie (HttpOnly, durée 24h)
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   3600 * 24,
		})
	} else {
		sessionID = cookie.Value
	}

	// Accès protégé à la map des sessions
	sessionMu.Lock()
	defer sessionMu.Unlock()
	entry, ok := sessionStore[sessionID]
	if !ok {
		// Nouvelle session : génération d'une clé AES-256 aléatoire
		key := make([]byte, 32)
		rand.Read(key)
		sessionStore[sessionID] = sessionEntry{key: key, lastUsed: time.Now()}
		return key
	}
	// Mise à jour de la date de dernière utilisation
	entry.lastUsed = time.Now()
	sessionStore[sessionID] = entry
	return entry.key
}

// cleanOldSessions supprime périodiquement (toutes les heures) les sessions inactives
// depuis plus de 24 heures afin de libérer la mémoire.
func cleanOldSessions() {
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		for range ticker.C {
			sessionMu.Lock()
			now := time.Now()
			for id, entry := range sessionStore {
				if now.Sub(entry.lastUsed) > 24*time.Hour {
					delete(sessionStore, id)
				}
			}
			sessionMu.Unlock()
		}
	}()
}

// ============================================================
// TEMPLATE PRINCIPAL (interface utilisateur moderne et animée)
// ============================================================

// baseTpl contient le code HTML/CSS commun à toutes les pages.
// On y trouve la barre latérale, l'avatar avec rotation 360°, les animations,
// le style responsive et les classes d'alerte.
const baseTpl = `
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes">
<title>Plateforme Cybersécurité M2 • RATSIMBAZAFY Emile</title>
<style>
/* Reset et variables CSS */
* { margin:0; padding:0; box-sizing:border-box; }

:root {
    --primary: #0f172a;
    --secondary: #1e293b;
    --accent: #4caf50;
    --accent-light: #6fbf6f;
    --text-light: #f1f5f9;
    --text-dark: #0f172a;
    --card-bg: rgba(255,255,255,0.85);
    --transition: all 0.3s cubic-bezier(0.2, 0.9, 0.4, 1.1);
}

body {
    font-family: 'Segoe UI', 'Inter', system-ui, sans-serif;
    background: linear-gradient(135deg, #eef2f8 0%, #d9e2ef 100%);
    margin:0;
    padding:0;
    color: var(--text-dark);
    backdrop-filter: blur(2px);
}

.container { display:flex; min-height:100vh; flex-wrap: wrap; }

/* Sidebar moderne (menu latéral) */
.sidebar {
    width:280px;
    background: linear-gradient(145deg, #0f172a, #0a0f1c);
    backdrop-filter: blur(10px);
    color: var(--text-light);
    min-height:100vh;
    padding: 28px 20px;
    box-shadow: 8px 0 24px rgba(0,0,0,0.2);
    transition: var(--transition);
    position: relative;
    z-index: 10;
}

.sidebar h3 {
    font-weight:700;
    margin-bottom:28px;
    font-size:1.3rem;
    border-left:4px solid var(--accent);
    padding-left:16px;
    background: linear-gradient(135deg, #fff, #94a3b8);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
}

.sidebar a {
    display:flex;
    align-items:center;
    gap:12px;
    color:#cbd5e1;
    text-decoration:none;
    padding:12px 16px;
    margin:8px 0;
    border-radius:16px;
    transition: var(--transition);
    font-weight:500;
    background: rgba(255,255,255,0.02);
}

.sidebar a:hover {
    background: rgba(76,175,80,0.15);
    color:white;
    transform:translateX(6px);
    box-shadow: 0 4px 12px rgba(0,0,0,0.2);
}

.sidebar a.active {
    background: rgba(76,175,80,0.25);
    color: var(--accent);
    border-left:3px solid var(--accent);
    font-weight:600;
}

/* Avatar : rotation horizontale continue (360° sur l'axe Y) */
.avatar {
    width:120px;
    height:120px;
    border-radius:50%;
    border:3px solid var(--accent);
    display:block;
    margin:30px auto 20px auto;
    object-fit:cover;
    transition: transform 0.2s ease, box-shadow 0.3s;
    box-shadow: 0 12px 28px rgba(0,0,0,0.3);
    animation: spinHorizontal 8s infinite linear;
    transform-style: preserve-3d;
    backface-visibility: visible;
}

.avatar:hover {
    animation-play-state: paused;  /* pause au survol */
    transform: scale(1.02);
    box-shadow: 0 20px 35px rgba(0,0,0,0.4);
}

@keyframes spinHorizontal {
    0% { transform: rotateY(0deg); }
    100% { transform: rotateY(360deg); }
}

/* Contenu principal */
.main {
    flex:1;
    padding: 32px 40px;
    max-width: 1200px;
    animation: fadeSlideUp 0.6s ease-out;
}

@keyframes fadeSlideUp {
    from { opacity:0; transform: translateY(30px); }
    to { opacity:1; transform: translateY(0); }
}

/* Cartes et formulaires avec effet glassmorphisme */
form, .card, .metric {
    background: var(--card-bg);
    backdrop-filter: blur(8px);
    border-radius: 32px;
    padding: 24px 28px;
    margin-bottom: 24px;
    box-shadow: 0 8px 20px rgba(0,0,0,0.05);
    border: 1px solid rgba(255,255,255,0.5);
    transition: var(--transition);
}

form:hover, .metric:hover {
    transform: translateY(-4px);
    box-shadow: 0 16px 28px rgba(0,0,0,0.1);
    background: rgba(255,255,255,0.95);
}

input, textarea, select {
    width:100%;
    padding: 12px 16px;
    margin: 8px 0 20px 0;
    border-radius: 24px;
    border: 1px solid #cbd5e1;
    background: #fff;
    font-size: 15px;
    transition: 0.2s;
}

input:focus, textarea:focus {
    border-color: var(--accent);
    outline: none;
    box-shadow: 0 0 0 3px rgba(76,175,80,0.2);
    transform: scale(1.01);
}

button, input[type=submit] {
    background: linear-gradient(135deg, var(--primary), var(--secondary));
    color: white;
    border: none;
    border-radius: 40px;
    padding: 12px 28px;
    cursor: pointer;
    transition: var(--transition);
    font-size: 15px;
    font-weight: 600;
    box-shadow: 0 4px 8px rgba(0,0,0,0.1);
}

button:hover, input[type=submit]:hover {
    background: linear-gradient(135deg, #1e3a5f, #0f2a44);
    transform: translateY(-2px);
    box-shadow: 0 10px 20px rgba(0,0,0,0.15);
}

/* Alertes animées */
.alert {
    padding: 16px 20px;
    border-radius: 28px;
    margin: 20px 0;
    font-weight: 500;
    animation: gentlePop 0.5s ease-out;
    backdrop-filter: blur(4px);
}

@keyframes gentlePop {
    0% { opacity:0; transform: scale(0.96); }
    80% { transform: scale(1.01); }
    100% { opacity:1; transform: scale(1); }
}

.error{ background:#fee2e2e6; color:#991b1b; border-left:6px solid #dc2626; }
.warning{ background:#fffbebe6; color:#92400e; border-left:6px solid #f59e0b; }
.info{ background:#e0f2fee6; color:#0c4a6e; border-left:6px solid #0ea5e9; }
.success{ background:#e0f2e9e6; color:#14532d; border-left:6px solid #22c55e; }

.metric {
    display:inline-flex;
    flex-direction: column;
    background: rgba(255,255,255,0.9);
    border-radius: 32px;
    padding: 16px 24px;
    margin: 8px 12px 8px 0;
    transition: var(--transition);
}

code, pre {
    background: #1e293b;
    color: #bbf7d0;
    padding: 16px;
    display: block;
    border-radius: 24px;
    white-space: pre-wrap;
    word-break: break-all;
    font-family: monospace;
    font-size: 13px;
    margin: 12px 0;
}

h1 { 
    font-size: 2.1rem; 
    background: linear-gradient(135deg, #0f172a, #2d3a5e);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
    margin-bottom: 8px;
}

h2 { font-size: 1.7rem; margin: 16px 0 12px; font-weight: 600; color: #0f172a; }
h3 { font-size: 1.3rem; margin: 20px 0 12px; font-weight: 600; }

hr { border: none; border-top: 2px solid rgba(0,0,0,0.08); margin: 28px 0; }

details {
    background: #f8fafc;
    padding: 16px 24px;
    border-radius: 32px;
    margin: 20px 0;
}
summary { cursor: pointer; font-weight: 600; }

/* Grille pour les ressources externes (liens CVE) */
.resources-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
    margin: 20px 0;
}
.resource-card {
    background: var(--card-bg);
    border-radius: 24px;
    padding: 16px 20px;
    flex: 1 1 180px;
    text-align: center;
    transition: var(--transition);
}
.resource-card:hover {
    transform: translateY(-5px);
    background: white;
}
.resource-card a {
    text-decoration: none;
    font-weight: 600;
    display: block;
    margin-top: 8px;
    color: var(--primary);
}
.resource-card a:hover { color: var(--accent); }

/* Responsive pour petits écrans */
@media (max-width: 768px) {
    .container { flex-direction: column; }
    .sidebar { width: 100%; min-height: auto; padding: 16px; text-align: center; }
    .sidebar a { justify-content: center; }
    .main { padding: 20px; }
    .avatar { width: 90px; height: 90px; }
    h1 { font-size: 1.6rem; }
}
</style>
</head>
<body>
<div class="container">
  <div class="sidebar">
    <h3>📂 Navigation</h3>
    <a href="/" class="{{if eq .Active "accueil"}}active{{end}}">🏠 Accueil</a>
    <a href="/vulnerabilites" class="{{if eq .Active "vuln"}}active{{end}}">🔍 1. Analyse Vulnérabilités</a>
    <a href="/securite-fichier" class="{{if eq .Active "fichier"}}active{{end}}">🔧 2. Développement Logiciels Sécurité</a>
    <a href="/pentest" class="{{if eq .Active "pentest"}}active{{end}}">🎯 3. Tests d'Intrusion</a>
    <a href="/ingenierie-sociale" class="{{if eq .Active "social"}}active{{end}}">🎣 4. Ingénierie Sociale</a>
    <a href="/cryptographie" class="{{if eq .Active "crypto"}}active{{end}}">🔐 5. Cryptographie</a>
    <a href="/a-propos" class="{{if eq .Active "apropos"}}active{{end}}">📄 À propos</a>
    <img class="avatar" src="/static/moi.png" alt="Avatar utilisateur" onerror="this.src='https://via.placeholder.com/120?text=Photo'">
    <hr>
    <p>RATSIMBAZAFY M.N Emile<br>M2 Cybersécurité • 2026</p>
  </div>
  <div class="main">
    <h1>🛡️ Plateforme Cybersécurité • Analyse, Protection & Cryptographie</h1>
    <hr>
    {{.Content}}  <!-- Injection du contenu spécifique à chaque page -->
  </div>
</div>
</body>
</html>
`

// tmpl est le template parsé une fois au démarrage pour optimiser les performances.
var tmpl = template.Must(template.New("base").Parse(baseTpl))

// pageData structure utilisée pour passer le contenu HTML et l'onglet actif au template.
type pageData struct {
	Content template.HTML
	Active  string
}

// render est une fonction utilitaire pour afficher une page avec le bon onglet actif.
func render(w http.ResponseWriter, active string, contentHTML string) {
	tmpl.Execute(w, pageData{Content: template.HTML(contentHTML), Active: active})
}

// ============================================================
// PAGE D'ACCUEIL
// ============================================================
func homeHandler(w http.ResponseWriter, r *http.Request) {
	content := `
<div class="alert info">✨ Bienvenue sur votre plateforme de cybersécurité interactive ✨</div>
<p>Cette application pédagogique illustre <b>cinq modules fondamentaux</b> de la cybersécurité :</p>
<ul>
<li>🔍 <b>Analyse de vulnérabilités</b> : simulateur CVSS, accès aux bases CVE, analyse de fichiers téléchargés</li>
<li>🔧 <b>Développement logiciels sécurité</b> : analyse heuristique de fichiers (flags, secrets, fonctions dangereuses)</li>
<li>🎯 <b>Tests d'intrusion</b> : scan de ports simulé (aucun paquet réel)</li>
<li>🎣 <b>Ingénierie sociale</b> : détection de phishing et quiz de sensibilisation</li>
<li>🔐 <b>Cryptographie</b> : chiffrement/déchiffrement AES-GCM avec clé par session</li>
</ul>
<p>Utilisez le menu latéral pour naviguer entre les modules.</p>
<div class="alert warning">⚠️ <b>Avertissement pédagogique</b> : Toutes les actions sont simulées à des fins éducatives uniquement.</div>
`
	render(w, "accueil", content)
}

// ============================================================
// FONCTION D'ANALYSE DE SÉCURITÉ (réutilisée dans les modules 1 et 2)
// ============================================================
// analyserSecuriteFichier examine le contenu d'un fichier (octets) et retourne :
//   - score : niveau de risque (0-100)
//   - menaces : liste des alertes graves
//   - indicateurs : liste des observations techniques
//
// Les détections incluent : flags CTF, clés API, tokens, fonctions dangereuses,
// URLs d'exfiltration, extensions exécutables.
func analyserSecuriteFichier(data []byte, filename string) (int, []string, []string) {
	score := 0
	var menaces []string
	var indicateurs []string

	texte := string(data)
	lowerTexte := strings.ToLower(texte)
	lowerFilename := strings.ToLower(filename)

	// Détection de flags (ex: flag{...}, CTF{...})
	flagPatterns := []string{`flag\{[^}]+\}`, `\{flag[^}]+\}`, `ctf\{[^}]+\}`, `FLAG\{[^}]+\}`}
	for _, p := range flagPatterns {
		re := regexp.MustCompile(p)
		if m := re.FindString(texte); m != "" {
			score += 30
			menaces = append(menaces, fmt.Sprintf("🏁 <b>Flag détecté</b> : %s", template.HTMLEscapeString(m)))
			indicateurs = append(indicateurs, "Contient un flag CTF")
			break
		}
	}

	// Motifs de secrets (clés API, jetons)
	secretPatterns := []struct {
		pattern string
		desc    string
	}{
		{`(?i)(api[_-]?key|apikey|token|secret|password)\s*[=:]\s*["']?([A-Za-z0-9_\-]{16,})`, "Clé API longue"},
		{`sk-[A-Za-z0-9]{32,}`, "Clé OpenAI suspecte"},
		{`ghp_[A-Za-z0-9]{36}`, "Token GitHub"},
		{`[A-Za-z0-9+/]{40,}={0,2}`, "Chaîne base64 suspecte"},
	}
	for _, sp := range secretPatterns {
		if matched, _ := regexp.MatchString(sp.pattern, texte); matched {
			score += 25
			menaces = append(menaces, fmt.Sprintf("🔑 <b>Secret probable</b> : %s", sp.desc))
			indicateurs = append(indicateurs, sp.desc)
			break
		}
	}

	// Fonctions dangereuses (eval, exec, system, etc.)
	dangerous := []string{"eval(", "exec(", "system(", "subprocess.", "os.system", "pickle.loads", "yaml.load(", "powershell", "cmd.exe"}
	for _, fn := range dangerous {
		if strings.Contains(lowerTexte, fn) {
			score += 20
			menaces = append(menaces, fmt.Sprintf("⚠️ Fonction dangereuse : <code>%s</code>", fn))
			indicateurs = append(indicateurs, "Appel à fonction système")
			break
		}
	}

	// URLs suspectes (exfiltration vers pastebin, ngrok, webhook Discord)
	urlRe := regexp.MustCompile(`https?://[^\s'"<>]+`)
	for _, u := range urlRe.FindAllString(texte, -1) {
		if strings.Contains(strings.ToLower(u), "pastebin") || strings.Contains(strings.ToLower(u), "ngrok") || strings.Contains(strings.ToLower(u), "discord.com/api/webhook") {
			score += 15
			menaces = append(menaces, fmt.Sprintf("🌐 Exfiltration possible : %s", template.HTMLEscapeString(u)))
			indicateurs = append(indicateurs, "URL vers service externe")
			break
		}
	}

	// Extensions de fichiers exécutables
	execExts := []string{".exe", ".bat", ".ps1", ".vbs", ".js", ".jar"}
	for _, ext := range execExts {
		if strings.HasSuffix(lowerFilename, ext) {
			score += 15
			menaces = append(menaces, fmt.Sprintf("📦 Extension exécutable : %s", template.HTMLEscapeString(filename)))
			indicateurs = append(indicateurs, "Fichier exécutable")
			break
		}
	}

	// Le score maximal est 100
	if score > 100 {
		score = 100
	}
	return score, menaces, indicateurs
}

// ============================================================
// MODULE 1 : ANALYSE DE VULNÉRABILITÉS (simulateur CVSS + liens CVE + analyse de fichier)
// ============================================================
func vulnHandler(w http.ResponseWriter, r *http.Request) {
	// Partie 1 : simulateur CVSS
	content := `<h2>🔍 Gestionnaire de Vulnérabilités (Simulation CVSS)</h2>
<form method="POST" action="/vulnerabilites">
<label>Identifiant CVE simulé</label>
<input type="text" name="cve" value="{{CVE}}">
<label>Note CVSS (Score de Gravité) : <span id="scoreVal">{{SCORE}}</span></label>
<input type="range" name="score" min="0" max="10" step="0.1" value="{{SCORE}}" oninput="document.getElementById('scoreVal').innerText=this.value">
<input type="submit" value="Analyser la Vulnérabilité">
</form>`

	cve := "CVE-2024-XXXX"
	scoreStr := "7.5"
	var resultat string

	// Traitement du formulaire CVSS (POST sans action spécifique)
	if r.Method == "POST" && r.FormValue("cve") != "" && r.FormValue("score") != "" {
		r.ParseForm()
		cve = r.FormValue("cve")
		scoreStr = r.FormValue("score")
		score, _ := strconv.ParseFloat(scoreStr, 64)

		switch {
		case score >= 7.0:
			resultat = fmt.Sprintf(`<div class="alert error">⚠️ <b>%s</b> : Vulnérabilité <b>CRITIQUE</b> (Score: %.1f)<br>Actions : Correctif immédiat !</div>`, template.HTMLEscapeString(cve), score)
		case score >= 4.0:
			resultat = fmt.Sprintf(`<div class="alert warning">📌 <b>%s</b> : Vulnérabilité <b>MOYENNE</b> (Score: %.1f)<br>Planifier mise à jour sous 2 semaines.</div>`, template.HTMLEscapeString(cve), score)
		default:
			resultat = fmt.Sprintf(`<div class="alert success">✅ <b>%s</b> : Vulnérabilité <b>MINEURE</b> (Score: %.1f)</div>`, template.HTMLEscapeString(cve), score)
		}
	}

	content = strings.Replace(content, "{{CVE}}", template.HTMLEscapeString(cve), 1)
	content = strings.Replace(content, "{{SCORE}}", scoreStr, 2)
	content += resultat

	// Partie 2 : Liens vers des bases de données CVE réelles (ressources externes)
	content += `<hr><h3>🌐 Sources de CVE réelles</h3>
<div class="resources-grid">
    <div class="resource-card">
        <span>📘 NVD (NIST)</span>
        <a href="https://nvd.nist.gov/vuln/search" target="_blank" rel="noopener noreferrer">Rechercher une CVE →</a>
    </div>
    <div class="resource-card">
        <span>🔍 CVE Details</span>
        <a href="https://www.cvedetails.com/" target="_blank" rel="noopener noreferrer">Explorer les vulnérabilités →</a>
    </div>
    <div class="resource-card">
        <span>🐙 GitHub Advisory DB</span>
        <a href="https://github.com/advisories" target="_blank" rel="noopener noreferrer">Consulter les avis →</a>
    </div>
    <div class="resource-card">
        <span>⚠️ Exploit-DB</span>
        <a href="https://www.exploit-db.com/" target="_blank" rel="noopener noreferrer">Chercher des exploits →</a>
    </div>
</div>
<p class="small">Cliquez sur les liens pour consulter des vulnérabilités existantes. Vous pouvez télécharger des rapports ou correctifs depuis ces sites, puis les analyser ci-dessous.</p>`

	// Partie 3 : Upload d'un fichier (rapport CVE, patch, etc.) et analyse avec la fonction commune
	content += `<hr><h3>📂 Analyser un fichier téléchargé (rapport CVE, correctif, etc.)</h3>
<form method="POST" action="/vulnerabilites" enctype="multipart/form-data">
<input type="hidden" name="action" value="analyze_file">
<label>Choisissez un fichier à analyser :</label>
<input type="file" name="fichier_cve">
<input type="submit" value="🔬 Analyser le fichier">
</form>`

	// Traitement de l'upload et analyse
	if r.Method == "POST" && r.FormValue("action") == "analyze_file" {
		r.ParseMultipartForm(32 << 20) // limite 32 Mo
		file, header, err := r.FormFile("fichier_cve")
		if err == nil {
			defer file.Close()
			buf := make([]byte, header.Size)
			file.Read(buf)

			nom := header.Filename
			taille := len(buf)
			hash := sha256.Sum256(buf)
			hashHex := hex.EncodeToString(hash[:])

			score, menaces, indicateurs := analyserSecuriteFichier(buf, nom)

			content += `<div class="card" style="margin-top:20px;">`
			content += fmt.Sprintf(`
<div class="metric"><b>Fichier analysé</b><br>%s</div>
<div class="metric"><b>Taille</b><br>%d bytes</div>
<div class="metric"><b>SHA-256</b><br>%s</div>
`, template.HTMLEscapeString(nom), taille, hashHex[:16]+"...")

			// Affichage du niveau de risque
			switch {
			case score >= 70:
				content += fmt.Sprintf(`<div class="alert error">🛑 Niveau de risque CRITIQUE : %d%%</div>`, score)
			case score >= 40:
				content += fmt.Sprintf(`<div class="alert warning">⚠️ Niveau de risque ÉLEVÉ : %d%%</div>`, score)
			case score >= 10:
				content += fmt.Sprintf(`<div class="alert info">🔵 Niveau de risque MODÉRÉ : %d%%</div>`, score)
			default:
				content += fmt.Sprintf(`<div class="alert success">✅ Niveau de risque FAIBLE : %d%%</div>`, score)
			}

			if len(menaces) > 0 {
				content += "<h3>🚨 Éléments suspects détectés :</h3><ul>"
				for _, m := range menaces {
					content += fmt.Sprintf("<li>%s</li>", m)
				}
				content += "</ul>"
			} else {
				content += `<div class="alert info">Aucune menace évidente dans ce fichier.</div>`
			}

			if len(indicateurs) > 0 {
				content += "<details><summary>📋 Indicateurs techniques</summary><ul>"
				for _, ind := range indicateurs {
					content += fmt.Sprintf("<li>%s</li>", ind)
				}
				content += "</ul></details>"
			}
			content += `</div>`
		} else {
			content += `<div class="alert warning">Erreur lors du téléchargement du fichier. Veuillez réessayer.</div>`
		}
	}

	render(w, "vuln", content)
}

// ============================================================
// MODULE 2 : DÉVELOPPEMENT LOGICIELS SÉCURITÉ (analyse de fichiers)
// ============================================================
func securiteFichierHandler(w http.ResponseWriter, r *http.Request) {
	content := `<h2>🛠️ Analyse de sécurité de fichiers (heuristique)</h2>
<p>Détection : malwares simulés, flags CTF, clés API, mots de passe, commandes shell.</p>
<form method="POST" action="/securite-fichier" enctype="multipart/form-data">
<label>📂 Téléchargez un fichier à analyser</label>
<input type="file" name="fichier">
<input type="submit" value="Analyser">
</form>`

	if r.Method == "POST" {
		r.ParseMultipartForm(32 << 20)
		file, header, err := r.FormFile("fichier")
		if err == nil {
			defer file.Close()
			buf := make([]byte, header.Size)
			file.Read(buf)

			nom := header.Filename
			taille := len(buf)
			hash := sha256.Sum256(buf)
			hashHex := hex.EncodeToString(hash[:])

			score, menaces, indicateurs := analyserSecuriteFichier(buf, nom)

			content += "<hr>"
			content += fmt.Sprintf(`
<div class="metric"><b>Fichier</b><br>%s</div>
<div class="metric"><b>Taille</b><br>%d bytes</div>
<div class="metric"><b>SHA-256</b><br>%s</div>
`, template.HTMLEscapeString(nom), taille, hashHex[:16]+"...")

			switch {
			case score >= 70:
				content += fmt.Sprintf(`<div class="alert error">🛑 Niveau de risque CRITIQUE : %d%%</div>`, score)
			case score >= 40:
				content += fmt.Sprintf(`<div class="alert warning">⚠️ Niveau de risque ÉLEVÉ : %d%%</div>`, score)
			case score >= 10:
				content += fmt.Sprintf(`<div class="alert info">🔵 Niveau de risque MODÉRÉ : %d%%</div>`, score)
			default:
				content += fmt.Sprintf(`<div class="alert success">✅ Niveau de risque FAIBLE : %d%%</div>`, score)
			}

			if len(menaces) > 0 {
				content += "<h3>🚨 Éléments suspects détectés :</h3><ul>"
				for _, m := range menaces {
					content += fmt.Sprintf("<li>%s</li>", m)
				}
				content += "</ul>"
			} else {
				content += `<div class="alert info">Aucune menace évidente.</div>`
			}

			content += "<details><summary>📋 Indicateurs techniques</summary><ul>"
			for _, ind := range indicateurs {
				content += fmt.Sprintf("<li>%s</li>", ind)
			}
			content += "</ul></details>"
		} else {
			content += `<div class="alert warning">Erreur lors de l'upload.</div>`
		}
	}
	render(w, "fichier", content)
}

// ============================================================
// MODULE 3 : TESTS D'INTRUSION (scan de ports simulé)
// ============================================================
func pentestHandler(w http.ResponseWriter, r *http.Request) {
	content := `<h2>🔎 Scan de ports (Simulation Éthique)</h2>
<form method="POST" action="/pentest">
<label>Adresse IP / Domaine à scanner (ex: exemple.com)</label>
<input type="text" name="cible" value="{{CIBLE}}">
<input type="submit" value="Lancer le scan simulé">
</form>`

	cible := "exemple.com"
	if r.Method == "POST" {
		r.ParseForm()
		cible = r.FormValue("cible")
		// Liste des ports courants avec leur service
		ports := map[int]string{80: "HTTP", 443: "HTTPS", 22: "SSH", 3389: "RDP", 3306: "MySQL"}
		ordre := []int{80, 443, 22, 3389, 3306}
		openPorts := []string{}
		// Simulation aléatoire (50% de chances d'être ouvert)
		for _, p := range ordre {
			if mrand.Float64() > 0.5 {
				openPorts = append(openPorts, fmt.Sprintf("%d (%s)", p, ports[p]))
				content += fmt.Sprintf(`<div class="alert warning">⚠️ Port <b>%d</b> (%s) : OUVERT</div>`, p, ports[p])
			} else {
				content += fmt.Sprintf(`<div class="alert info">✅ Port <b>%d</b> (%s) : FERMÉ</div>`, p, ports[p])
			}
		}
		if len(openPorts) > 0 {
			content += fmt.Sprintf(`<div class="alert error">Résumé : ports exposés → %s</div>`, strings.Join(openPorts, ", "))
		} else {
			content += `<div class="alert success">Aucun port sensible ouvert.</div>`
		}
		content += `<p class="small">🔒 Simulation uniquement, aucun paquet réel envoyé.</p>`
	}
	content = strings.Replace(content, "{{CIBLE}}", template.HTMLEscapeString(cible), 1)
	render(w, "pentest", content)
}

// ============================================================
// MODULE 4 : INGÉNIERIE SOCIALE (détection phishing + quiz)
// ============================================================

// analyserPhishing examine une URL et retourne un score de suspicion (0-100)
// ainsi qu'une liste d'indicateurs (longueur, caractère '@', adresse IP, sous-domaines douteux, TLD inhabituels).
func analyserPhishing(rawURL string) (int, []string) {
	score := 0
	var indicateurs []string

	// Critères simples mais pédagogiques
	if len(rawURL) > 75 {
		score += 20
		indicateurs = append(indicateurs, "URL très longue")
	}
	if strings.Contains(rawURL, "@") {
		score += 30
		indicateurs = append(indicateurs, "Contient '@' (tentative d'usurpation)")
	}
	ipRe := regexp.MustCompile(`https?://\d+\.\d+\.\d+\.\d+`)
	if ipRe.MatchString(rawURL) {
		score += 25
		indicateurs = append(indicateurs, "Adresse IP utilisée (pas de nom de domaine)")
	}
	parsed, _ := url.Parse(rawURL)
	domaine := strings.ToLower(parsed.Host)
	suspectWords := []string{"secure", "login", "verify", "account", "update", "confirm"}
	for _, w := range suspectWords {
		if strings.Contains(domaine, w) && strings.Count(domaine, ".") > 1 {
			score += 15
			indicateurs = append(indicateurs, fmt.Sprintf("Sous-domaine suspect : '%s'", w))
			break
		}
	}
	tlds := []string{".tk", ".ml", ".ga", ".cf", ".top", ".xyz", ".work"}
	for _, tld := range tlds {
		if strings.HasSuffix(domaine, tld) {
			score += 15
			indicateurs = append(indicateurs, fmt.Sprintf("TLD inhabituel : %s", tld))
			break
		}
	}
	if score > 100 {
		score = 100
	}
	return score, indicateurs
}

func ingenierieSocialeHandler(w http.ResponseWriter, r *http.Request) {
	lienValue := ""
	selectedQuiz := ""
	var linkResultHTML string
	var quizResultHTML string

	if r.Method == "POST" {
		r.ParseForm()
		action := r.FormValue("action")
		if action == "analyser_lien" {
			lien := r.FormValue("lien")
			lienValue = lien
			selectedQuiz = r.FormValue("quiz_prev")
			if strings.TrimSpace(lien) == "" {
				linkResultHTML = `<div class="alert warning">Veuillez saisir un lien à analyser.</div>`
			} else {
				score, indicateurs := analyserPhishing(lien)
				var verdict string
				switch {
				case score >= 60:
					linkResultHTML += fmt.Sprintf(`<div class="alert error">⚠️ Risque élevé : %d%%</div>`, score)
					verdict = "PHISHING PROBABLE"
				case score >= 30:
					linkResultHTML += fmt.Sprintf(`<div class="alert warning">⚠️ Risque modéré : %d%%</div>`, score)
					verdict = "SUSPECT"
				default:
					linkResultHTML += fmt.Sprintf(`<div class="alert success">✅ Risque faible : %d%%</div>`, score)
					verdict = "SEMBLE SÛR"
				}
				if len(indicateurs) > 0 {
					linkResultHTML += "<p><b>Indicateurs :</b></p><ul>"
					for _, ind := range indicateurs {
						linkResultHTML += fmt.Sprintf("<li>%s</li>", ind)
					}
					linkResultHTML += "</ul>"
				}
				linkResultHTML += fmt.Sprintf(`<p><small>🔎 Verdict : %s — Ne cliquez jamais sur un lien suspect sans vérification.</small></p>`, verdict)
			}
		} else if action == "quiz" {
			lienValue = r.FormValue("lien_prev")
			selectedQuiz = r.FormValue("quiz")
			correct := "Je vérifie l'adresse e-mail de l'expéditeur et je saisis l'URL manuellement dans mon navigateur."
			if selectedQuiz == correct {
				quizResultHTML = `<div class="alert success">✅ Bonne réponse ! Toujours vérifier l'expéditeur et utiliser le site officiel.</div>`
			} else if selectedQuiz != "" {
				quizResultHTML = `<div class="alert error">❌ Mauvais réflexe. Ne cliquez jamais sur un lien non sollicité.</div>`
			}
		}
	}

	content := `<h2>🎣 Analyse de liens suspects & sensibilisation</h2>
<h3>🔗 Analysez un lien</h3>
<form method="POST" action="/ingenierie-sociale">
<input type="hidden" name="action" value="analyser_lien">
<input type="hidden" name="quiz_prev" value="{{QUIZPREV}}">
<label>Entrez une URL suspecte :</label>
<input type="text" name="lien" placeholder="ex: https://paypal-securite-urgent.com" value="{{LIEN}}">
<input type="submit" value="🔍 Analyser">
</form>`
	content = strings.Replace(content, "{{LIEN}}", template.HTMLEscapeString(lienValue), 1)
	content = strings.Replace(content, "{{QUIZPREV}}", template.HTMLEscapeString(selectedQuiz), 1)
	content += linkResultHTML

	// Quiz à choix unique
	reponses := []string{
		"Je clique sur le lien immédiatement pour éviter un blocage.",
		"Je vérifie l'adresse e-mail de l'expéditeur et je saisis l'URL manuellement dans mon navigateur.",
		"Je transfère l'e-mail à un ami pour avoir son avis.",
	}
	content += `<hr><h3>📧 Quiz : e-mail de phishing</h3>
<p>Vous recevez un e-mail urgent de votre banque avec un lien. Que faites-vous ?</p>
<form method="POST" action="/ingenierie-sociale">
<input type="hidden" name="action" value="quiz">
<input type="hidden" name="lien_prev" value="{{LIEN}}">`
	content = strings.Replace(content, "{{LIEN}}", template.HTMLEscapeString(lienValue), 1)
	for _, rep := range reponses {
		checked := ""
		if selectedQuiz == rep {
			checked = "checked"
		}
		content += fmt.Sprintf(`<label><input type="radio" name="quiz" value="%s" %s> %s</label><br>`, template.HTMLEscapeString(rep), checked, rep)
	}
	content += `<input type="submit" value="Voir la réponse"></form>` + quizResultHTML

	render(w, "social", content)
}

// ============================================================
// MODULE 5 : CRYPTOGRAPHIE (AES-GCM avec clé par session)
// ============================================================

// aesEncrypt chiffre un texte clair avec la clé donnée (AES-256 en mode GCM).
// Retourne le ciphertext encodé en base64URL (incluant le nonce).
func aesEncrypt(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// aesDecrypt déchiffre un message encodé en base64URL avec la clé fournie.
func aesDecrypt(key []byte, encoded string) (string, error) {
	data, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext invalide")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func cryptographieHandler(w http.ResponseWriter, r *http.Request) {
	// Récupération de la clé de session (propre à l'utilisateur)
	key := getSessionKey(w, r)
	content := `<h2>🔐 Chiffrement AES (clé par session)</h2>
<p>Chaque session dispose d'une clé unique stockée côté serveur (cookie sécurisé).</p>`
	var dernierChiffre, erreurDechiffrement, messageDechiffre string
	msgAChiffrer := "Hello world"

	if r.Method == "POST" {
		r.ParseForm()
		switch r.FormValue("action") {
		case "chiffrer":
			msgAChiffrer = r.FormValue("msg_chiffrer")
			if enc, err := aesEncrypt(key, msgAChiffrer); err == nil {
				dernierChiffre = enc
			}
		case "dechiffrer":
			msg := r.FormValue("msg_dechiffrer")
			dernierChiffre = msg
			if strings.TrimSpace(msg) == "" {
				erreurDechiffrement = "Veuillez fournir un message chiffré."
			} else if dec, err := aesDecrypt(key, msg); err != nil {
				erreurDechiffrement = "Erreur de déchiffrement (clé différente ou altération)."
			} else {
				messageDechiffre = dec
			}
		}
	}

	// Formulaire de chiffrement
	content += `<h3>🔒 Chiffrer</h3>
<form method="POST" action="/cryptographie">
<input type="hidden" name="action" value="chiffrer">
<label>Message clair</label>
<textarea name="msg_chiffrer" rows="3">` + template.HTMLEscapeString(msgAChiffrer) + `</textarea>
<input type="submit" value="🔒 Chiffrer">
</form>`
	if dernierChiffre != "" && messageDechiffre == "" && erreurDechiffrement == "" {
		content += fmt.Sprintf(`<pre>%s</pre>`, template.HTMLEscapeString(dernierChiffre))
	}

	// Formulaire de déchiffrement
	content += `<hr><h3>🔓 Déchiffrer</h3>
<form method="POST" action="/cryptographie">
<input type="hidden" name="action" value="dechiffrer">
<label>Message chiffré (base64)</label>
<textarea name="msg_dechiffrer" rows="3">` + template.HTMLEscapeString(dernierChiffre) + `</textarea>
<input type="submit" value="🔓 Déchiffrer">
</form>`
	if erreurDechiffrement != "" {
		content += fmt.Sprintf(`<div class="alert error">%s</div>`, erreurDechiffrement)
	}
	if messageDechiffre != "" {
		content += fmt.Sprintf(`<div class="alert success">Message déchiffré : %s</div>`, template.HTMLEscapeString(messageDechiffre))
	}
	render(w, "crypto", content)
}

// ============================================================
// PAGE "À PROPOS"
// ============================================================
func aProposHandler(w http.ResponseWriter, r *http.Request) {
	content := `<h2>📄 À propos de la plateforme</h2>
<p>Application développée par <b>RATSIMBAZAFY Miandrisoa Notahinjanahary Emile</b>, étudiant M2 Cybersécurité – Université d'Amoron'i Mania.</p>
<p>Projet pédagogique couvrant : analyse de vulnérabilités, détection de malwares, tests d'intrusion, sensibilisation au phishing et cryptographie.</p>
<p><b>Année :</b> 2025–2026<br><b>But :</b> démonstration éthique des bonnes pratiques de cybersécurité.</p>
<p>© 2026 – Tous droits réservés.</p>`
	render(w, "apropos", content)
}

// ============================================================
// FONCTION MAIN (point d'entrée)
// ============================================================
func main() {
	// Initialisation du générateur aléatoire pour les simulations
	mrand.Seed(time.Now().UnixNano())
	// Lancement du nettoyage périodique des sessions
	cleanOldSessions()

	// Serveur de fichiers statiques (les fichiers sont intégrés dans l'exécutable)
	http.Handle("/static/", http.FileServer(http.FS(staticFiles)))

	// Enregistrement des routes
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/vulnerabilites", vulnHandler)
	http.HandleFunc("/securite-fichier", securiteFichierHandler)
	http.HandleFunc("/pentest", pentestHandler)
	http.HandleFunc("/ingenierie-sociale", ingenierieSocialeHandler)
	http.HandleFunc("/cryptographie", cryptographieHandler)
	http.HandleFunc("/a-propos", aProposHandler)

	// Démarrage du serveur HTTP
	fmt.Println("🚀 Serveur démarré sur http://localhost:8080")
	fmt.Println("🆕 Sur la page Analyse vulnérabilités : accès aux bases CVE externes + téléchargement/analyse de fichiers")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Println("Erreur:", err)
	}
}
