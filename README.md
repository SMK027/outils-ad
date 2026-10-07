# outils-ad

## Gestion-Partages.ps1

Script PowerShell interactif (menu) de gestion des dossiers partagés sur Windows Server 2022 dans un domaine Active Directory.
Le fichier est en ASCII pur (aucun accent) pour éviter les problèmes d'encodage avec Windows PowerShell 5.1.

### Fonctions

| Menu | Action |
|------|--------|
| 1 | Lister les partages (hors partages système) et afficher le détail des droits SMB/NTFS |
| 2 | Ajouter un ou plusieurs utilisateurs/groupes à un partage (accès standard) |
| 3 | Ajouter un ou plusieurs gestionnaires du dossier `Depot` (lecture/modification) |
| 4 | Retirer l'accès (SMB + NTFS) à un ou plusieurs utilisateurs/groupes |
| 5 | Créer un nouveau partage avec la structure standard |
| 6 | Créer une GPO de mappage de lecteur pour un partage qui n'est pas encore mappé |
| 7 | Appliquer les droits actuels du dossier `Depot` à un partage déjà créé (partages créés avec une version précédente du script) |

### Structure d'un partage créé

```
<Racine>        Administrateurs/Système : contrôle total (héritage coupé)
 |              Membres : lecture, ce dossier seulement
 |-- Commun     Membres + gestionnaires : lecture/modification
 |              (le dossier Commun lui-même ne peut être ni supprimé ni renommé)
 |-- Depot      Membres : dépôt uniquement (création + liste du dossier, aucune lecture des fichiers)
                Auteur d'un dépôt : peut remplacer/supprimer son propre fichier, sans le relire
                Gestionnaires : lecture/modification
```

- L'énumération basée sur l'accès (ABE) est **activée et indispensable** : l'explorateur Windows doit pouvoir lister le dossier de destination pour y copier un fichier ; les membres ont donc le droit de lister `Depot`, et l'ABE n'y affiche que les éléments qu'ils peuvent lire, c'est-à-dire aucun. Le dossier leur apparaît **vide**, même après un dépôt.
- **Déposer un fichier** : ouvrir `Depot` et coller/glisser le fichier (ou le déposer sur l'icône du dossier). Le fichier disparaît de l'affichage une fois copié : c'est normal.
- Un membre ne peut ni voir, ni lire, ni écraser les fichiers déposés par les autres. Deux dépôts portant le même nom entrent en conflit : le second est refusé, il faut nommer les fichiers de façon unique (ex. `NOM_Prenom.docx`).
- Droit de partage SMB : `Modifier` pour chaque compte ajouté, `Contrôle total` pour les Administrateurs.
- Dans `Depot`, une ACE `OWNER RIGHTS` empêche l'auteur d'un dépôt de relire son fichier grâce aux droits implicites du propriétaire.
- Si un partage existant n'a pas les sous-dossiers `Commun`/`Depot`, l'ajout d'un compte donne la lecture/modification sur tout le partage (après confirmation).

### Saisie simplifiée

- **Utilisateurs/groupes** : tapez une partie du login, du nom ou du nom affiché (`compta`, `dupont`...). Les résultats sont numérotés ; sélection par `1,3,5-7` ou `*`. Plusieurs recherches peuvent s'enchaîner, Entrée vide pour terminer.
- **OU (GPO)** : navigation par numéro, `P` pour remonter, `R` pour rechercher une OU par nom, `V` pour valider, `A` pour annuler.
- Toute saisie invalide (format, compte ou OU introuvable) affiche un message et redemande la valeur ; les erreurs d'une action sont interceptées et le script revient au menu.

### GPO de mappage

- Le script analyse les préférences « Mappages de lecteurs » de toutes les GPO du domaine : seuls les partages non mappés sont proposés et les lettres déjà utilisées sont signalées.
- La GPO est créée sur le contrôleur PDC (préférence utilisateur `Mettre à jour`, reconnexion), liée à l'OU choisie, partie ordinateur désactivée.
- Filtrage de sécurité facultatif : comptes ayant accès au partage ou comptes recherchés. Les « Utilisateurs authentifiés » conservent alors la lecture seule (nécessaire depuis MS16-072).
- En cas d'échec, la GPO incomplète est supprimée.
- La détection des mappages existants compare le nom de serveur (court ou FQDN) ; un mappage via un alias DNS n'est pas détecté.

### Prérequis

À exécuter **en administrateur sur le serveur de fichiers** :

```powershell
Install-WindowsFeature RSAT-AD-PowerShell, GPMC
```

Le compte doit avoir les droits de création/liaison de GPO dans le domaine.

### Utilisation

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Gestion-Partages.ps1                      # dossier parent par défaut : D:\Partages (ou C:\Partages)
.\Gestion-Partages.ps1 -BasePath E:\Partages
.\Gestion-Partages.ps1 -CommonFolderName Commun -DepotFolderName Depot
```
