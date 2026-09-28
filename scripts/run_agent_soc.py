



import os
import sqlite3
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ajouter le répertoire parent au path pour les imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Load environment variables from .env (if present)
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    # Continue gracefully if python-dotenv is not installed; env vars can be set externally
    pass

try:
    import google.generativeai as genai
except ImportError:
    print("❌ Le package 'google-generativeai' n'est pas installé.")
    print("👉 Installe-le avec : pip install google-generativeai")
    sys.exit(1)

# ── 1. Configuration de l'API Gemini ──────────────────────────────
# L'agent a besoin d'une clé API Gemini définie dans les variables d'environnement.
# Tu peux en obtenir une gratuitement sur Google AI Studio.
API_KEY = os.environ.get("GEMINI_API_KEY")
if not API_KEY:
    print("⚠️  Variable d'environnement GEMINI_API_KEY non trouvée.")
    print("Définis-la sous Windows (PowerShell) avec :")
    print('   $env:GEMINI_API_KEY="ta_cle_api_ici"')
    print("Puis relance le script.")
    # On continue avec une simulation hors-ligne si pas de clé pour que le script ne crash pas immédiatement
    print("\n--- Exécution en mode démo (simulation de l'agent) ---\n")
else:
    genai.configure(api_key=API_KEY)

# ── 2. Définition des Outils (Tools) ───────────────────────────────

def query_nuclei_kb(search_query: str) -> str:
    """Recherche dans la base de connaissances des templates Nuclei par mot-clé, tag ou URI.

    Args:
        search_query: Le mot-clé, le nom du protocole, de la CVE ou l'URI à rechercher.
    """
    db_path = Path(__file__).resolve().parent.parent / "data" / "nuclei_kb.db"
    if not db_path.exists():
        return "Erreur : Base de données SQLite non trouvée. Lance le pipeline d'abord."

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Recherche floue dans les champs clés
    cursor.execute("""
        SELECT template_id, name, severity, cve_id, description, file_path 
        FROM templates 
        WHERE tags LIKE ? OR name LIKE ? OR description LIKE ? OR file_path LIKE ?
        LIMIT 3
    """, (f"%{search_query}%", f"%{search_query}%", f"%{search_query}%", f"%{search_query}%"))
    
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    
    if not rows:
        return f"Aucun template correspondant trouvé pour '{search_query}'."
    return str(rows)

def model_ml_predict(packet_size: int, duration: float, protocol: str) -> str:
    """Exécute le modèle de Machine Learning pour prédire si un flux réseau est malveillant ou sain.

    Args:
        packet_size: La taille moyenne des paquets du flux en octets.
        duration: La durée du flux réseau en secondes.
        protocol: Le protocole réseau (ex: http, dns, tcp, ssl).
    """
    # Ici, tu chargerais ton vrai modèle ML (ex: XGBoost ou PyTorch)
    # Pour ce test, nous simulons la logique du modèle :
    packet_size = int(packet_size)
    duration = float(duration)
    
    if packet_size > 1500 and protocol.lower() == "http":
        return f"Alerte ML : Anomalie critique détectée (Score: 0.94). Motif: Requête HTTP anormalement volumineuse ({packet_size} octets)."
    elif protocol.lower() == "dns" and packet_size > 500:
        return f"Alerte ML : Anomalie suspecte détectée (Score: 0.78). Motif: Tunneling DNS potentiel."
    else:
        return "Flux normal détecté par le modèle ML."

# ── 3. Lancement de l'Agent ───────────────────────────────────────

def run_agent_demo():
    """Simule le raisonnement de l'agent si aucune clé API n'est fournie."""
    print("🤖 [Agent IA - Simulation]")
    print("Alerte d'entrée : Requête HTTP suspecte de 1800 octets ciblant '/wp-content/plugins/wp-db/readme.txt'")
    print("-" * 50)
    
    # Étape 1 : Appel du modèle ML
    print("1. Appel outil: model_ml_predict(packet_size=1800, duration=0.5, protocol='http')")
    ml_result = model_ml_predict(1800, 0.5, "http")
    print(f"   ↳ Retour: {ml_result}")
    
    # Étape 2 : Appel de la base Nuclei
    print("2. Appel outil: query_nuclei_kb(search_query='wp-db')")
    kb_result = query_nuclei_kb("wp-db")
    print(f"   ↳ Retour: {kb_result}")
    
    # Étape 3 : Rapport final
    print("\n3. Rapport d'incident généré par l'Agent :")
    print(
        "L'analyse du flux montre une anomalie validée à 94% par le modèle ML en raison d'une taille de paquet excessive.\n"
        "La base Nuclei a identifié un template correspondant ('wp-db-plugin-vuln') ciblant ce plugin WordPress.\n"
        "Recommandation : Bloquer l'IP source et désactiver ou patcher le plugin WordPress WP-DB sur le serveur cible."
    )

def run_real_agent():
    """Exécute l'agent réel avec l'API Gemini et le tool calling automatique."""
    print("🤖 Démarrage de l'agent IA SOC (Gemini)...")
    
    # Initialisation du modèle avec les fonctions déclarées comme outils
    model = genai.GenerativeModel(
        model_name="gemini-1.5-flash",
        tools=[query_nuclei_kb, model_ml_predict],
        system_instruction=(
            "Tu es un analyste SOC Senior. Ton rôle est d'analyser les alertes réseau. "
            "Tu dois utiliser l'outil 'model_ml_predict' pour évaluer la suspicion d'un flux réseau, "
            "puis utiliser 'query_nuclei_kb' pour chercher si une vulnérabilité connue correspond. "
            "Enfin, rédige un rapport d'incident structuré en français avec des actions de remédiation."
        )
    )
    
    # Démarre une session de chat avec appel automatique des fonctions
    chat = model.start_chat(enable_automatic_function_calling=True)
    
    prompt = (
        "Enquête sur cette alerte : Nous avons détecté un flux HTTP suspect de 1800 octets, "
        "d'une durée de 0.5s, ciblant le chemin '/wp-content/plugins/wp-db/readme.txt'."
    )
    
    print(f"\nPrompt envoyé à l'Agent :\n👉 {prompt}\n")
    print("Raisonnement en cours (Gemini appelle les outils en arrière-plan)...")
    
    response = chat.send_message(prompt)
    
    print("\n📝 Rapport Final de l'Agent :\n")
    print(response.text)


if __name__ == "__main__":
    if API_KEY:
        run_real_agent()
    else:
        run_agent_demo()
