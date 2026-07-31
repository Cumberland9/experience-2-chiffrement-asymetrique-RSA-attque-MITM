import hashlib
import rsa
import streamlit as st

st.title("Attaque MITM et Protection")

# Création des onglets pour séparer l'attaque et la protection
onglet1, onglet2 = st.tabs(
    ["Expérience RSA (Essai A & B)", "Protection (Empreinte)"]
)

TAILLE_CLE = 2048  # 512 bits est trop faible (factorisable en pratique) ;
                    # 2048 bits est la taille minimale recommandée aujourd'hui.

# ----------------------------------------------------
# ONGLET 1 : Essai A et Essai B
# ----------------------------------------------------
with onglet1:
    st.header("Simulation des Essais A et B")
    message = st.text_input("Message d'Alice à Bob", "Bonjour Bob !")

    mode = st.radio(
        "Choisir le scénario :", ["Essai A (Normal)", "Essai B (MITM)"]
    )

    modification_active = False
    if mode == "Essai B (MITM)":
        modification_active = st.checkbox(
            "Eve modifie le message avant de le retransmettre à Bob"
        )

    if st.button("Lancer la communication"):
        try:
            # 1. Bob génère ses clés
            pub_bob, priv_bob = rsa.newkeys(TAILLE_CLE)

            if mode == "Essai A (Normal)":
                # Alice chiffre directement avec la clé de Bob
                message_chiffre = rsa.encrypt(message.encode(), pub_bob)
                # Bob déchiffre
                message_dechiffre = rsa.decrypt(message_chiffre, priv_bob).decode()

                st.success("Communication normale réussie !")
                st.write("Message déchiffré par Bob :", message_dechiffre)
                st.info(
                    "Eve a vu la clé et le texte chiffré, mais ne peut pas "
                    "lire sans la clé privée de Bob."
                )

            else:
                # Essai B : Attaque MITM
                # 2-3. Eve intercepte la tentative d'envoi et génère sa propre paire de clés
                pub_eve, priv_eve = rsa.newkeys(TAILLE_CLE)

                # 4-5. Alice chiffre avec la clé publique d'Eve, en croyant que c'est celle de Bob
                message_chiffre_par_eve = rsa.encrypt(message.encode(), pub_eve)

                # 6-7. Eve intercepte et déchiffre avec sa clé privée
                message_intercepte = rsa.decrypt(
                    message_chiffre_par_eve, priv_eve
                ).decode()

                # 8. Eve peut lire, et éventuellement modifier, le message
                message_transmis = message_intercepte
                if modification_active:
                    message_transmis = message_intercepte + " [c'est Alice]"

                # 9. Eve rechiffre avec la véritable clé publique de Bob
                message_chiffre_pour_bob = rsa.encrypt(
                    message_transmis.encode(), pub_bob
                )

                # 10. Bob reçoit et déchiffre
                message_dechiffre_bob = rsa.decrypt(
                    message_chiffre_pour_bob, priv_bob
                ).decode()

                st.warning("Attaque MITM réussie par Eve !")
                st.write(
                    "1. Eve a intercepté et lu le message en clair :"
                    f" **{message_intercepte}**"
                )
                if modification_active:
                    st.write(
                        "2. Eve a modifié le message avant de le retransmettre :"
                        f" **{message_transmis}**"
                    )
                st.write("3. Bob a reçu :", message_dechiffre_bob)
                st.error(
                    "Pourquoi ? Parce qu'Alice n'a pas vérifié l'identité de "
                    "la clé reçue. Eve n'a pas cassé RSA : elle a simplement "
                    "substitué sa propre clé publique à celle de Bob."
                )

        except OverflowError:
            st.error(
                "Le message est trop long pour être chiffré directement "
                "avec cette taille de clé RSA. Essayez un message plus court."
            )

# ----------------------------------------------------
# ONGLET 2 : Protection contre l'attaque MITM
# ----------------------------------------------------
with onglet2:
    st.header("Protection : Vérification de l'empreinte")
    st.write(
        "Pour contrer l'attaque, Alice compare l'empreinte (hash) de la clé "
        "publique reçue avec une empreinte de référence obtenue à l'avance "
        "par un canal sécurisé (ex. rencontre en personne, certificat, "
        "annuaire de confiance)."
    )

    # On génère UNE FOIS la vraie clé de Bob et son empreinte de référence,
    # comme si Alice l'avait obtenue au préalable par un canal sécurisé.
    if "pub_bob_ref" not in st.session_state:
        st.session_state.pub_bob_ref, st.session_state.priv_bob_ref = rsa.newkeys(
            TAILLE_CLE
        )
        st.session_state.empreinte_ref = hashlib.sha256(
            str(st.session_state.pub_bob_ref).encode()
        ).hexdigest()

    scenario = st.radio(
        "Quelle clé Alice reçoit-elle au moment de la communication ?",
        ["La vraie clé de Bob", "Une clé substituée par Eve (MITM)"],
    )

    if st.button("Tester la vérification"):
        if scenario == "La vraie clé de Bob":
            cle_recue = st.session_state.pub_bob_ref
        else:
            cle_recue, _ = rsa.newkeys(TAILLE_CLE)  # fausse clé d'Eve

        empreinte_recue = hashlib.sha256(str(cle_recue).encode()).hexdigest()

        st.text(
            "Empreinte officielle (connue d'avance) : "
            + st.session_state.empreinte_ref[:15]
            + "..."
        )
        st.text("Empreinte de la clé reçue : " + empreinte_recue[:15] + "...")

        if empreinte_recue == st.session_state.empreinte_ref:
            st.success("Les empreintes correspondent. Clé authentique !")
        else:
            st.error(
                "ALERTE : Les empreintes ne correspondent pas ! Attaque "
                "MITM détectée."
            )
