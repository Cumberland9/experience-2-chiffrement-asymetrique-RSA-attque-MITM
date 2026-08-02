# Expérience 2 — RSA et attaque MITM
## Description
Cette application Streamlit simule une communication chiffrée avec RSA entre Alice et Bob. Elle démontre comment un message peut être chiffré et déchiffré, puis montre comment une attaque MITM peut se produire si la clé publique reçue n'est pas vérifiée.
## Objectifs
- Comprendre le fonctionnement du chiffrement asymétrique RSA
- Observer le rôle de la clé publique et de la clé privée de Bob
- Montrer comment Eve peut intercepter la communication et substituer sa propre clé publique
- Vérifier l'identité d'une clé publique grâce à son empreinte
## Fonctionnalités
- Génération d'une paire de clés RSA pour Bob
- Chiffrement d'un message en texte clair saisi par l'utilisateur
- Simulation de l'interception et de la substitution de clé par Eve
- Déchiffrement du message par Bob à l'aide de sa clé privée
- Vérification de l'empreinte de la clé publique pour détecter une attaque MITM
## Technologies utilisées
- Streamlit — interface utilisateur
- rsa — implémentation du chiffrement RSA
## Installation
```bash
pip install -r requirements.txt
```
## Auteur
Ilyass Taouani
