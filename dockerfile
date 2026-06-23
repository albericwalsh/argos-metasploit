FROM metasploitframework/metasploit-framework:latest

# Pas de modification nécessaire — l'image officielle MSF
# contient déjà msfconsole et toute la base de modules.
#
# Pour mettre à jour la base de modules à la construction :
# RUN msfupdate || true

ENTRYPOINT ["/usr/src/metasploit-framework/msfconsole"]
