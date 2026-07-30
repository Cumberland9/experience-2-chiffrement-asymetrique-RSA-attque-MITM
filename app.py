import hashlib
import rsa
import streamlit as st

st.title("TP RSA - Attaque MITM et Protection")

# Création des onglets pour séparer l'attaque et la protection
onglet1, onglet2 = st.tabs(
    ["Expérience RSA (Essai A & B)", "Protection (Empreinte)"]
)

# ----------------------------------------------------
# ONGLET 1 : Essai A et Essai B
# ----------------------------------------------------
with onglet1:
  st.header("Simulation des Essais A et B")

  message = st.text_input("Message d'Alice à Bob", "Bonjour Bob !")

  # Choix du mode (Normal ou Attaque)
  mode = st.radio("Choisir le scénario :", ["Essai A (Normal)", "Essai B (MITM)"])

  if st.button("Lancer la communication"):
    # 1. Bob génère ses clés
    pub_bob, priv_bob = rsa.newkeys(512)

    if mode == "Essai A (Normal)":
      # Alice chiffre directement avec la clé de Bob
      message_chiffre = rsa.encrypt(message.encode(), pub_bob)

      # Bob déchiffre
      message_dechiffre = rsa.decrypt(message_chiffre, priv_bob).decode()

      st.success("Communication normale réussie !")
      st.write("Message déchiffré par Bob :", message_dechiffre)
      st.info(
          "Eve a vu la clé et le texte chiffré, mais ne peut pas lire sans la"
          " clé privée de Bob."
      )

    else:
      # Essai B : Attaque MITM
      # Eve génère sa propre paire de clés
      pub_eve, priv_eve = rsa.newkeys(512)

      # Alice chiffre avec la clé d'Eve (en croyant que c'est celle de Bob)
      message_chiffre_par_eve = rsa.encrypt(message.encode(), pub_eve)

      # Eve intercepte et déchiffre avec sa clé privée
      message_intercepté = rsa.decrypt(message_chiffre_par_eve, priv_eve).decode()

      # Eve rechiffre avec la vraie clé de Bob
      message_chiffre_pour_bob = rsa.encrypt(message_intercepté.encode(), pub_bob)

      # Bob reçoit et déchiffre
      message_dechiffre_bob = rsa.decrypt(
          message_chiffre_pour_bob, priv_bob
      ).decode()

      st.warning("Attaque MITM réussie par Eve !")
      st.write(
          "1. Eve a intercepté et lu le message en clair :"
          f" **{message_intercepté}**"
      )
      st.write("2. Bob a reçu :", message_dechiffre_bob)
      st.error(
          "Pourquoi ? Parce qu'Alice n'a pas vérifié l'identité de la clé"
          " reçue."
      )

# ----------------------------------------------------
# ONGLET 2 : Protection contre l'attaque MITM
# ----------------------------------------------------
with onglet2:
  st.header("Protection : Vérification de l'empreinte")
  st.write(
      "Pour contrer l'attaque, on compare l'empreinte (hash) de la clé"
      " publique avec un canal de confiance."
  )

  if st.button("Tester la vérification"):
    # Génération des clés
    pub_bob, priv_bob = rsa.newkeys(512)
    pub_eve, priv_eve = rsa.newkeys(512)  # Fausse clé d'Eve

    # On calcule l'empreinte de la vraie clé de Bob
    empreinte_officielle = hashlib.sha256(str(pub_bob).encode()).hexdigest()

    # Supposons qu'Eve essaie d'envoyer sa clé
    empreinte_recue = hashlib.sha256(str(pub_eve).encode()).hexdigest()

    st.text("Empreinte officielle (connue d'avance) : " + empreinte_officielle[:15] + "...")
    st.text("Empreinte de la clé reçue : " + empreinte_recue[:15] + "...")

    # Comparaison
    if empreinte_recue == empreinte_officielle:
      st.success("Les empreintes correspondent. Clé authentique !")
    else:
      st.error(
          "ALERTE : Les empreintes ne correspondent pas ! Attaque MITM"
          " détectée."
      )
