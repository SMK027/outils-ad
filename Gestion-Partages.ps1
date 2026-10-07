<#
.SYNOPSIS
    Gestion des dossiers partages sur Windows Server 2022 (domaine Active Directory).

.DESCRIPTION
    Script interactif (menu) permettant de :
      1. Lister les partages existants (et afficher le detail des droits)
      2. Ajouter un ou plusieurs utilisateurs/groupes du domaine a un partage (acces standard)
      3. Ajouter un ou plusieurs utilisateurs/groupes en gestionnaire du dossier Depot
         (lecture/modification sur le dossier de depot)
      4. Retirer l'acces a un partage pour un ou plusieurs utilisateurs/groupes
      5. Creer un nouveau partage avec la structure standard
      6. Creer une GPO de mappage de lecteur pour un partage qui n'est pas deja mappe

    Structure creee pour un nouveau partage :

        <Racine>            lecture seule (ce dossier uniquement) pour les membres du partage
         |-- Commun         lecture/modification pour tous les membres du partage
         |-- Depot          depot uniquement : creation de fichiers sans lecture du contenu
                            (les gestionnaires du depot ont lecture/modification)

    Le fichier est volontairement ecrit en ASCII pur (aucun accent) afin d'eviter
    les problemes d'encodage avec Windows PowerShell 5.1.

.PARAMETER BasePath
    Dossier parent propose par defaut pour la creation des nouveaux partages.
    Par defaut : D:\Partages si le lecteur D: existe, sinon C:\Partages.

.PARAMETER CommonFolderName
    Nom du sous-dossier commun (defaut : Commun).

.PARAMETER DepotFolderName
    Nom du sous-dossier de depot (defaut : Depot).

.EXAMPLE
    .\Gestion-Partages.ps1

.EXAMPLE
    .\Gestion-Partages.ps1 -BasePath 'E:\Partages'

.NOTES
    Prerequis (a executer sur le serveur de fichiers, en administrateur) :
      - Module SmbShare (natif)
      - Module ActiveDirectory   : Install-WindowsFeature RSAT-AD-PowerShell
      - Module GroupPolicy       : Install-WindowsFeature GPMC
    Le compte utilise doit pouvoir creer/lier des GPO dans le domaine.
#>
#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$BasePath,
    [string]$CommonFolderName = 'Commun',
    [string]$DepotFolderName = 'Depot'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# =====================================================================
#  Constantes
# =====================================================================

$FSR = [System.Security.AccessControl.FileSystemRights]
$IFL = [System.Security.AccessControl.InheritanceFlags]
$PFL = [System.Security.AccessControl.PropagationFlags]

# Droits NTFS utilises par le script
$script:Rights = @{
    FullControl    = $FSR::FullControl
    Read           = $FSR::ReadAndExecute
    Modify         = $FSR::Modify
    # Modification sur le dossier lui-meme mais sans pouvoir le supprimer/renommer
    ModifyNoDelete = [System.Security.AccessControl.FileSystemRights]([int]$FSR::Modify -band (-bnot [int]$FSR::Delete))
    # Depot : traverser + creer fichiers/dossiers, sans lister le contenu
    DepotFolder    = $FSR::Traverse -bor $FSR::CreateFiles -bor $FSR::CreateDirectories -bor `
                     $FSR::ReadAttributes -bor $FSR::ReadExtendedAttributes -bor $FSR::Synchronize
    # Depot : ecrire dans un fichier sans pouvoir le lire. N'est plus attribue aux membres
    # (ils pourraient ecraser les fichiers des autres) ; conserve pour reconnaitre et
    # supprimer cette ACE sur les partages crees par une version precedente du script.
    DepotFiles     = $FSR::WriteData -bor $FSR::AppendData -bor $FSR::WriteAttributes -bor `
                     $FSR::WriteExtendedAttributes -bor $FSR::Synchronize
}
# OWNER RIGHTS : seul l'auteur d'un depot peut ecrire/remplacer/supprimer SON fichier,
# toujours sans pouvoir le relire.
$script:Rights.OwnerRights = $script:Rights.DepotFolder -bor $script:Rights.DepotFiles -bor $FSR::Delete

$script:Inherit = @{
    None = $IFL::None
    CI   = $IFL::ContainerInherit
    OI   = $IFL::ObjectInherit
    Both = $IFL::ContainerInherit -bor $IFL::ObjectInherit
}
$script:Propagate = @{
    None        = $PFL::None
    InheritOnly = $PFL::InheritOnly
}

# SID bien connus
$script:SidAdmins    = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$script:SidSystem    = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$script:SidOwnerRights = New-Object System.Security.Principal.SecurityIdentifier('S-1-3-4')
$script:SidAuthUsers = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-11')
$script:ProtectedSids = @('S-1-5-32-544', 'S-1-5-18', 'S-1-3-0', 'S-1-3-4')

# Partages systeme a ne jamais proposer
$script:ExcludedShares = @('SYSVOL', 'NETLOGON')

# Extensions GPP "Drive Maps" (Preferences > Mappages de lecteurs)
$script:DriveMapsExtensions = '[{00000000-0000-0000-0000-000000000000}{2EA1A81B-48E5-45E9-8BB7-A6E3AC170006}]' +
                              '[{5794DAFD-BE60-433F-88A2-1A31939AC01F}{2EA1A81B-48E5-45E9-8BB7-A6E3AC170006}]'

# Contexte d'execution (rempli par Initialize-Environment)
$script:Ctx = [ordered]@{
    AdOk      = $false
    GpOk      = $false
    DomainDns = $null
    DomainDN  = $null
    NetBios   = $null
    DomainSid = $null
    Server    = $null
    Fqdn      = $null
}

# =====================================================================
#  Affichage / saisie
# =====================================================================

function Write-Title([string]$Text) {
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor Cyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor Cyan
}
function Write-Info([string]$Text) { Write-Host $Text }
function Write-Ok([string]$Text)   { Write-Host "[OK] $Text" -ForegroundColor Green }
function Write-Warn([string]$Text) { Write-Host "[ATTENTION] $Text" -ForegroundColor Yellow }
function Write-Err([string]$Text)  { Write-Host "[ERREUR] $Text" -ForegroundColor Red }

function Wait-Return {
    [void](Read-Host "`nAppuyez sur Entree pour revenir au menu")
}

function Read-Text {
    param(
        [string]$Prompt,
        [string]$Default,
        [switch]$AllowEmpty
    )
    while ($true) {
        $label = $Prompt
        if ($Default) { $label = "$Prompt [$Default]" }
        $value = Read-Host $label
        if ($null -eq $value) { $value = '' }
        $value = $value.Trim()
        if (-not $value -and $Default) { return $Default }
        if ($value -or $AllowEmpty) { return $value }
        Write-Warn 'Une valeur est obligatoire.'
    }
}

function Read-YesNo {
    param(
        [string]$Prompt,
        [bool]$Default = $false
    )
    $suffix = if ($Default) { '(O/n)' } else { '(o/N)' }
    while ($true) {
        $value = Read-Host "$Prompt $suffix"
        if ($null -eq $value) { $value = '' }
        $value = $value.Trim()
        if (-not $value) { return $Default }
        if ($value -match '^(o|oui|y|yes)$') { return $true }
        if ($value -match '^(n|non|no)$') { return $false }
        Write-Warn 'Repondez par O (oui) ou N (non).'
    }
}

# Convertit "1,3,5-7" ou "*" en liste d'index (base 1). Retourne $null si invalide.
function ConvertTo-IndexList {
    param([string]$Text, [int]$Max)
    $Text = $Text.Trim()
    if ($Text -eq '*') { return @(1..$Max) }
    $result = New-Object System.Collections.Generic.List[int]
    foreach ($part in ($Text -split '[,; ]+' | Where-Object { $_ })) {
        if ($part -match '^(\d+)-(\d+)$') {
            $a = [int]$Matches[1]; $b = [int]$Matches[2]
            if ($a -gt $b) { $tmp = $a; $a = $b; $b = $tmp }
            if ($a -lt 1 -or $b -gt $Max) { return $null }
            foreach ($i in $a..$b) { $result.Add($i) }
        }
        elseif ($part -match '^\d+$') {
            $n = [int]$part
            if ($n -lt 1 -or $n -gt $Max) { return $null }
            $result.Add($n)
        }
        else { return $null }
    }
    return @($result | Sort-Object -Unique)
}

# Demande une selection de numeros. Retourne un tableau d'index (base 1), vide si annulation.
function Read-Selection {
    param(
        [int]$Max,
        [string]$Prompt = 'Numero(s) (ex: 1,3,5-7 ou * pour tous, Entree pour annuler)',
        [switch]$Single
    )
    if ($Single -and $Prompt -like 'Numero(s)*') { $Prompt = 'Numero (Entree pour annuler)' }
    while ($true) {
        $value = Read-Host $Prompt
        if ($null -eq $value -or -not $value.Trim()) { return @() }
        $idx = ConvertTo-IndexList -Text $value -Max $Max
        if ($null -eq $idx -or @($idx).Count -eq 0) {
            Write-Warn "Saisie invalide. Entrez un ou plusieurs numeros entre 1 et $Max."
            continue
        }
        if ($Single -and @($idx).Count -gt 1) {
            Write-Warn 'Un seul numero est attendu.'
            continue
        }
        return @($idx)
    }
}

# =====================================================================
#  Outils SID / noms
# =====================================================================

function ConvertTo-Sid([string]$AccountName) {
    try {
        return (New-Object System.Security.Principal.NTAccount($AccountName)).Translate([System.Security.Principal.SecurityIdentifier])
    } catch { }
    try {
        return New-Object System.Security.Principal.SecurityIdentifier($AccountName)
    } catch { }
    return $null
}

function ConvertTo-AccountName($Sid) {
    try { return $Sid.Translate([System.Security.Principal.NTAccount]).Value }
    catch { return $Sid.Value }
}

function Get-AdminsName { return ConvertTo-AccountName $script:SidAdmins }

# =====================================================================
#  Initialisation
# =====================================================================

function Initialize-Environment {
    Import-Module SmbShare -ErrorAction Stop

    if (-not $BasePath) {
        if (Test-Path -LiteralPath 'D:\') { $script:BasePath = 'D:\Partages' } else { $script:BasePath = 'C:\Partages' }
    } else {
        $script:BasePath = $BasePath
    }

    try {
        $script:Ctx.Fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
    } catch {
        $script:Ctx.Fqdn = $env:COMPUTERNAME
    }

    try {
        Import-Module ActiveDirectory -ErrorAction Stop -WarningAction SilentlyContinue
        $domain = Get-ADDomain -ErrorAction Stop
        $script:Ctx.DomainDns = $domain.DNSRoot
        $script:Ctx.DomainDN  = $domain.DistinguishedName
        $script:Ctx.NetBios   = $domain.NetBIOSName
        $script:Ctx.DomainSid = $domain.DomainSID.Value
        $script:Ctx.Server    = $domain.PDCEmulator
        $script:Ctx.AdOk      = $true
    } catch {
        Write-Warn "Module ActiveDirectory indisponible ou domaine injoignable : $($_.Exception.Message)"
        Write-Warn 'Installation : Install-WindowsFeature RSAT-AD-PowerShell'
        Write-Warn 'Seule la liste des partages sera disponible.'
    }

    if ($script:Ctx.AdOk) {
        try {
            Import-Module GroupPolicy -ErrorAction Stop -WarningAction SilentlyContinue
            $script:Ctx.GpOk = $true
        } catch {
            Write-Warn "Module GroupPolicy indisponible : $($_.Exception.Message)"
            Write-Warn 'Installation : Install-WindowsFeature GPMC'
        }
    }
}

function Assert-Ad {
    if (-not $script:Ctx.AdOk) {
        Write-Err 'Cette fonction necessite le module ActiveDirectory et un acces au domaine.'
        return $false
    }
    return $true
}

# =====================================================================
#  Recherche simplifiee des utilisateurs / groupes AD
# =====================================================================

# Echappe une saisie pour un filtre LDAP. Le caractere * est conserve comme joker.
function ConvertTo-LdapValue([string]$Text) {
    $sb = New-Object System.Text.StringBuilder
    foreach ($c in $Text.ToCharArray()) {
        switch ($c) {
            '\'  { [void]$sb.Append('\5c') }
            '('  { [void]$sb.Append('\28') }
            ')'  { [void]$sb.Append('\29') }
            ([char]0) { [void]$sb.Append('\00') }
            default { [void]$sb.Append($c) }
        }
    }
    return $sb.ToString()
}

function ConvertTo-Principal($AdObject) {
    $sid = $AdObject.objectSid
    $name = ConvertTo-AccountName $sid
    if ($name -eq $sid.Value -and $AdObject.sAMAccountName) {
        $name = "$($script:Ctx.NetBios)\$($AdObject.sAMAccountName)"
    }
    $class = [string]$AdObject.ObjectClass
    $type = switch ($class) {
        'group'    { 'Groupe' }
        'computer' { 'Ordinateur' }
        default    { 'Utilisateur' }
    }
    $label = $AdObject.Name
    if ($AdObject.PSObject.Properties['displayName'] -and $AdObject.displayName) { $label = $AdObject.displayName }
    return [pscustomobject]@{
        Name  = $name
        Sam   = $AdObject.sAMAccountName
        Sid   = $sid
        Class = $class
        Type  = $type
        Label = $label
    }
}

function Get-AdPrincipalBySid($Sid) {
    try {
        $o = Get-ADObject -LDAPFilter "(objectSid=$($Sid.Value))" -Server $script:Ctx.Server `
                -Properties objectSid, sAMAccountName, displayName -ErrorAction Stop
        if ($o) { return ConvertTo-Principal $o }
    } catch { }
    return $null
}

# Recherche interactive : on tape une partie du nom (login, nom ou nom affiche),
# on choisit les resultats par numero, on peut enchainer plusieurs recherches.
function Select-AdPrincipals {
    param([string]$Title = 'Selection des utilisateurs / groupes')

    $selected = New-Object System.Collections.Generic.List[object]
    Write-Host ''
    Write-Host "--- $Title ---" -ForegroundColor Cyan
    Write-Info 'Tapez une partie du nom, du login ou du nom affiche (ex: compta, dupont).'
    Write-Info 'Laissez vide et validez pour terminer la selection.'

    while ($true) {
        $term = Read-Host "`nRecherche"
        if ($null -eq $term) { $term = '' }
        $term = $term.Trim()
        if (-not $term) { break }

        $value = ConvertTo-LdapValue $term
        if ($value -notmatch '\*') { $value = "*$value*" }
        $filter = "(&(|(&(objectCategory=person)(objectClass=user))(objectCategory=group))" +
                  "(|(sAMAccountName=$value)(name=$value)(displayName=$value)))"
        try {
            $results = @(Get-ADObject -LDAPFilter $filter -Server $script:Ctx.Server -ResultSetSize 51 `
                            -Properties objectSid, sAMAccountName, displayName -ErrorAction Stop |
                         Sort-Object ObjectClass, Name)
        } catch {
            Write-Err "Recherche impossible : $($_.Exception.Message)"
            continue
        }
        if ($results.Count -eq 0) {
            Write-Warn "Aucun utilisateur ou groupe ne correspond a '$term'."
            continue
        }
        if ($results.Count -gt 50) {
            Write-Warn 'Plus de 50 resultats : seuls les 50 premiers sont affiches, affinez la recherche.'
            $results = $results[0..49]
        }

        $principals = @($results | ForEach-Object { ConvertTo-Principal $_ })
        for ($i = 0; $i -lt $principals.Count; $i++) {
            $p = $principals[$i]
            Write-Host ('  [{0,2}] {1,-12} {2,-40} {3}' -f ($i + 1), $p.Type, $p.Name, $p.Label)
        }
        $idx = @(Read-Selection -Max $principals.Count)
        foreach ($n in $idx) {
            $p = $principals[$n - 1]
            if (-not ($selected | Where-Object { $_.Sid.Value -eq $p.Sid.Value })) {
                $selected.Add($p)
            }
        }
        if ($selected.Count -gt 0) {
            Write-Info ('Selection actuelle : ' + (($selected | ForEach-Object { $_.Name }) -join ', '))
        }
    }
    return $selected.ToArray()
}

# =====================================================================
#  ACL NTFS
# =====================================================================

function Get-FolderAcl([string]$Path) {
    $di = New-Object System.IO.DirectoryInfo($Path)
    $sections = [System.Security.AccessControl.AccessControlSections]::Access
    if ($PSVersionTable.PSEdition -eq 'Core') {
        return [System.IO.FileSystemAclExtensions]::GetAccessControl($di, $sections)
    }
    return $di.GetAccessControl($sections)
}

function Set-FolderAcl([string]$Path, $Acl) {
    $di = New-Object System.IO.DirectoryInfo($Path)
    if ($PSVersionTable.PSEdition -eq 'Core') {
        [System.IO.FileSystemAclExtensions]::SetAccessControl($di, $Acl)
    } else {
        $di.SetAccessControl($Acl)
    }
}

function New-FsRule($Sid, $Rights, $Inherit, $Propagate) {
    return New-Object System.Security.AccessControl.FileSystemAccessRule(
        $Sid, $Rights, $Inherit, $Propagate, [System.Security.AccessControl.AccessControlType]::Allow)
}

function Add-FolderRules([string]$Path, [object[]]$Rules) {
    $acl = Get-FolderAcl $Path
    foreach ($r in $Rules) { $acl.AddAccessRule($r) }
    Set-FolderAcl $Path $acl
}

# Lecture/modification sans possibilite de supprimer ou renommer le dossier lui-meme
function Get-ModifyRules($Sid) {
    return @(
        (New-FsRule $Sid $script:Rights.ModifyNoDelete $script:Inherit.None $script:Propagate.None),
        (New-FsRule $Sid $script:Rights.Modify $script:Inherit.Both $script:Propagate.InheritOnly)
    )
}

# Depot : creation possible, aucun droit de lecture/liste. Les droits sur le fichier
# depose viennent de l'ACE OWNER RIGHTS (auteur du fichier uniquement).
function Get-DepotRules($Sid) {
    return @(
        (New-FsRule $Sid $script:Rights.DepotFolder $script:Inherit.CI $script:Propagate.None)
    )
}

function Get-OwnerRightsRule {
    return New-FsRule $script:SidOwnerRights $script:Rights.OwnerRights $script:Inherit.Both $script:Propagate.InheritOnly
}

function Get-RootReadRule($Sid) {
    return New-FsRule $Sid $script:Rights.Read $script:Inherit.None $script:Propagate.None
}

function Format-Rights($Rights) {
    $sync = [int]$FSR::Synchronize
    $v = [int]$Rights -band (-bnot $sync)
    $known = [ordered]@{
        'Controle total'                           = $script:Rights.FullControl
        'Modification'                             = $script:Rights.Modify
        'Modification (dossier non supprimable)'   = $script:Rights.ModifyNoDelete
        'Lecture'                                  = $script:Rights.Read
        'Depot (creation sans lecture)'            = $script:Rights.DepotFolder
        'Depot (ecriture fichiers sans lecture)'   = $script:Rights.DepotFiles
        'Depot (restriction proprietaire)'         = $script:Rights.OwnerRights
    }
    foreach ($k in $known.Keys) {
        if ($v -eq ([int]$known[$k] -band (-bnot $sync))) { return $k }
    }
    return $Rights.ToString()
}

function Format-AppliesTo($Rule) {
    $inh = $Rule.InheritanceFlags
    $io  = ($Rule.PropagationFlags -band $PFL::InheritOnly) -ne 0
    if ($inh -eq $script:Inherit.None) { return 'Ce dossier seulement' }
    if ($inh -eq $script:Inherit.Both -and -not $io) { return 'Dossier, sous-dossiers et fichiers' }
    if ($inh -eq $script:Inherit.Both -and $io) { return 'Sous-dossiers et fichiers' }
    if ($inh -eq $script:Inherit.CI -and -not $io) { return 'Dossier et sous-dossiers' }
    if ($inh -eq $script:Inherit.OI -and $io) { return 'Fichiers seulement' }
    return "$inh / $($Rule.PropagationFlags)"
}

# =====================================================================
#  Partages
# =====================================================================

# Selon la version du module SmbShare, ShareType est renvoye sous forme de nom
# (FileSystemDirectory, PrintQueue...) ou de valeur numerique brute (0, 1...) :
# on exclut donc explicitement les types non fichiers au lieu d'exiger un nom precis.
function Test-FileSystemShare($Share) {
    $type = [string]$Share.ShareType
    return ($type -notmatch '^(PrintQueue|CommunicationDevice|Ipc|1|2|3)$')
}

function Get-ManagedShares {
    return @(Get-SmbShare -ErrorAction Stop | Where-Object {
        -not $_.Special -and
        $_.Path -and
        $_.Name -notmatch '\$$' -and
        $script:ExcludedShares -notcontains $_.Name -and
        (Test-FileSystemShare $_)
    } | Sort-Object Name)
}

function Get-ShareLayout($Share) {
    $root = $Share.Path
    $commun = Join-Path $root $CommonFolderName
    $depot  = Join-Path $root $DepotFolderName
    $hasCommun = Test-Path -LiteralPath $commun -PathType Container
    $hasDepot  = Test-Path -LiteralPath $depot -PathType Container
    return [pscustomobject]@{
        Root       = $root
        Commun     = if ($hasCommun) { $commun } else { $null }
        Depot      = if ($hasDepot) { $depot } else { $null }
        Structured = ($hasCommun -and $hasDepot)
    }
}

function Get-LayoutPaths($Layout) {
    return @($Layout.Root, $Layout.Commun, $Layout.Depot | Where-Object { $_ })
}

function Select-Share {
    param([object[]]$Shares, [string]$Title = 'Choix du partage')
    if (-not $Shares) { $Shares = @(Get-ManagedShares) }
    if ($Shares.Count -eq 0) {
        Write-Warn 'Aucun partage disponible.'
        return $null
    }
    Write-Host ''
    Write-Host "--- $Title ---" -ForegroundColor Cyan
    for ($i = 0; $i -lt $Shares.Count; $i++) {
        Write-Host ('  [{0,2}] {1,-25} {2}' -f ($i + 1), $Shares[$i].Name, $Shares[$i].Path)
    }
    while ($true) {
        $value = Read-Host 'Numero ou nom du partage (Entree pour annuler)'
        if ($null -eq $value -or -not $value.Trim()) { return $null }
        $value = $value.Trim()
        if ($value -match '^\d+$') {
            $n = [int]$value
            if ($n -ge 1 -and $n -le $Shares.Count) { return $Shares[$n - 1] }
        } else {
            $match = @($Shares | Where-Object { $_.Name -ieq $value })
            if ($match.Count -eq 1) { return $match[0] }
        }
        Write-Warn "Partage '$value' introuvable. Entrez un numero de la liste ou un nom exact."
    }
}

function Get-SmbAccessEntries([string]$ShareName) {
    return @(Get-SmbShareAccess -Name $ShareName -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            AccountName = $_.AccountName
            Sid         = ConvertTo-Sid $_.AccountName
            Type        = [string]$_.AccessControlType
            Right       = [string]$_.AccessRight
        }
    })
}

function Grant-SmbChange([string]$ShareName, $Principal) {
    $existing = Get-SmbAccessEntries $ShareName | Where-Object {
        $_.Sid -and $_.Sid.Value -eq $Principal.Sid.Value -and $_.Type -eq 'Allow' -and $_.Right -in @('Full', 'Change')
    }
    if ($existing) { return }
    Grant-SmbShareAccess -Name $ShareName -AccountName $Principal.Name -AccessRight Change -Force -ErrorAction Stop | Out-Null
}

# Liste des comptes ayant un droit explicite sur le partage (SMB ou NTFS)
function Get-SharePrincipalEntries($Share, $Layout) {
    $map = [ordered]@{}
    foreach ($e in (Get-SmbAccessEntries $Share.Name)) {
        if (-not $e.Sid) {
            $key = $e.AccountName
            if (-not $map.Contains($key)) {
                $map[$key] = [pscustomobject]@{ Sid = $null; Name = $e.AccountName; SmbNames = New-Object System.Collections.Generic.List[string]; SmbRights = ''; Ntfs = $false }
            }
            $map[$key].SmbNames.Add($e.AccountName)
            continue
        }
        if ($script:ProtectedSids -contains $e.Sid.Value) { continue }
        $key = $e.Sid.Value
        if (-not $map.Contains($key)) {
            $map[$key] = [pscustomobject]@{ Sid = $e.Sid; Name = ConvertTo-AccountName $e.Sid; SmbNames = New-Object System.Collections.Generic.List[string]; SmbRights = ''; Ntfs = $false }
        }
        $map[$key].SmbNames.Add($e.AccountName)
        $map[$key].SmbRights = "$($e.Type)/$($e.Right)"
    }
    foreach ($path in (Get-LayoutPaths $Layout)) {
        $acl = Get-FolderAcl $path
        foreach ($r in $acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])) {
            $sid = $r.IdentityReference
            if ($script:ProtectedSids -contains $sid.Value) { continue }
            $key = $sid.Value
            if (-not $map.Contains($key)) {
                $map[$key] = [pscustomobject]@{ Sid = $sid; Name = ConvertTo-AccountName $sid; SmbNames = New-Object System.Collections.Generic.List[string]; SmbRights = ''; Ntfs = $false }
            }
            $map[$key].Ntfs = $true
        }
    }
    return @($map.Values)
}

# Attribue les droits d'un role a un compte sur un partage
function Grant-SharePrincipal {
    param($Share, $Layout, $Principal, [ValidateSet('Standard', 'Gestionnaire')][string]$Role)
    $sid = $Principal.Sid
    if ($Layout.Structured) {
        Add-FolderRules $Layout.Root @(Get-RootReadRule $sid)
        Add-FolderRules $Layout.Commun (Get-ModifyRules $sid)
        if ($Role -eq 'Gestionnaire') {
            Add-FolderRules $Layout.Depot (Get-ModifyRules $sid)
        } else {
            Add-FolderRules $Layout.Depot (Get-DepotRules $sid)
        }
    } else {
        Add-FolderRules $Layout.Root (Get-ModifyRules $sid)
    }
    Grant-SmbChange $Share.Name $Principal
}

function Revoke-SharePrincipal {
    param($Share, $Layout, $Entry)
    if ($Entry.Sid) {
        foreach ($path in (Get-LayoutPaths $Layout)) {
            $acl = Get-FolderAcl $path
            $acl.PurgeAccessRules($Entry.Sid)
            Set-FolderAcl $path $acl
        }
    }
    foreach ($n in ($Entry.SmbNames | Select-Object -Unique)) {
        Revoke-SmbShareAccess -Name $Share.Name -AccountName $n -Force -ErrorAction Stop | Out-Null
    }
}

# =====================================================================
#  1. Lister les partages
# =====================================================================

function Show-ShareDetail($Share) {
    $layout = Get-ShareLayout $Share
    Write-Title "Detail du partage $($Share.Name)"
    Write-Info "Chemin      : $($Share.Path)"
    Write-Info "UNC         : \\$($script:Ctx.Fqdn)\$($Share.Name)"
    Write-Info "Description : $($Share.Description)"
    Write-Info "Enumeration : $($Share.FolderEnumerationMode)"
    if ($layout.Structured) {
        Write-Info "Structure   : standard ($CommonFolderName / $DepotFolderName)"
    } else {
        Write-Warn "Structure non standard (sous-dossiers $CommonFolderName/$DepotFolderName absents)."
    }

    Write-Host "`nDroits de partage (SMB) :" -ForegroundColor Cyan
    foreach ($e in (Get-SmbAccessEntries $Share.Name)) {
        Write-Host ('  {0,-45} {1,-6} {2}' -f $e.AccountName, $e.Type, $e.Right)
    }

    foreach ($path in (Get-LayoutPaths $layout)) {
        Write-Host "`nDroits NTFS explicites sur $path :" -ForegroundColor Cyan
        $acl = Get-FolderAcl $path
        if ($acl.AreAccessRulesProtected) { Write-Info '  (heritage desactive)' }
        $rules = @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
        if ($rules.Count -eq 0) { Write-Info '  (aucun droit explicite, droits herites uniquement)' }
        foreach ($r in $rules) {
            Write-Host ('  {0,-40} {1,-6} {2,-40} {3}' -f (ConvertTo-AccountName $r.IdentityReference),
                $r.AccessControlType, (Format-Rights $r.FileSystemRights), (Format-AppliesTo $r))
        }
    }
}

function Show-Shares {
    Write-Title 'Partages existants'
    $shares = @(Get-ManagedShares)
    if ($shares.Count -eq 0) {
        Write-Warn 'Aucun partage (hors partages systeme) sur ce serveur.'
        return
    }
    Write-Host ('  {0,4} {1,-25} {2,-35} {3,-10} {4}' -f 'No', 'Nom', 'Chemin', 'Structure', 'Description')
    Write-Host ('  {0,4} {1,-25} {2,-35} {3,-10} {4}' -f '--', '---', '------', '---------', '-----------')
    for ($i = 0; $i -lt $shares.Count; $i++) {
        $s = $shares[$i]
        $layout = Get-ShareLayout $s
        $struct = if ($layout.Structured) { 'Standard' } else { 'Autre' }
        Write-Host ('  {0,4} {1,-25} {2,-35} {3,-10} {4}' -f ($i + 1), $s.Name, $s.Path, $struct, $s.Description)
    }
    while ($true) {
        Write-Host ''
        $idx = @(Read-Selection -Max $shares.Count -Single -Prompt 'Numero pour afficher le detail des droits (Entree pour terminer)')
        if ($idx.Count -eq 0) { return }
        try {
            Show-ShareDetail $shares[$idx[0] - 1]
        } catch {
            Write-Err "Impossible d'afficher le detail : $($_.Exception.Message)"
        }
    }
}

# =====================================================================
#  2/3. Ajouter des utilisateurs/groupes
# =====================================================================

function Add-ShareAccess {
    param([ValidateSet('Standard', 'Gestionnaire')][string]$Role = 'Standard')

    if (-not (Assert-Ad)) { return }
    if ($Role -eq 'Gestionnaire') {
        Write-Title "Ajouter un gestionnaire du dossier $DepotFolderName (lecture/modification)"
    } else {
        Write-Title 'Ajouter des utilisateurs/groupes a un partage'
    }

    $share = Select-Share
    if (-not $share) { return }
    $layout = Get-ShareLayout $share

    if (-not $layout.Structured) {
        if ($Role -eq 'Gestionnaire') {
            Write-Err "Le partage '$($share.Name)' ne contient pas de dossier $DepotFolderName : impossible d'ajouter un gestionnaire du depot."
            return
        }
        Write-Warn "Le partage '$($share.Name)' n'a pas la structure $CommonFolderName/$DepotFolderName."
        Write-Warn 'Les comptes recevront la lecture/modification sur tout le partage.'
        if (-not (Read-YesNo 'Continuer ?')) { return }
    }

    $principals = @(Select-AdPrincipals)
    if ($principals.Count -eq 0) {
        Write-Warn 'Aucun utilisateur/groupe selectionne, operation annulee.'
        return
    }

    Write-Host ''
    Write-Info "Partage : $($share.Name) ($($share.Path))"
    if ($layout.Structured) {
        Write-Info "Racine  : lecture (ce dossier seulement)"
        Write-Info "$CommonFolderName  : lecture/modification"
        if ($Role -eq 'Gestionnaire') {
            Write-Info "$DepotFolderName   : lecture/modification (gestionnaire)"
        } else {
            Write-Info "$DepotFolderName   : depot uniquement (sans lecture)"
        }
    }
    Write-Info ('Comptes : ' + (($principals | ForEach-Object { $_.Name }) -join ', '))
    if (-not (Read-YesNo 'Appliquer ces droits ?' $true)) { return }

    foreach ($p in $principals) {
        try {
            Grant-SharePrincipal -Share $share -Layout $layout -Principal $p -Role $Role
            Write-Ok "$($p.Name) ajoute au partage $($share.Name)."
        } catch {
            Write-Err "$($p.Name) : $($_.Exception.Message)"
        }
    }
}

# =====================================================================
#  4. Retirer l'acces
# =====================================================================

function Remove-ShareAccess {
    Write-Title "Retirer l'acces a un partage"
    $share = Select-Share
    if (-not $share) { return }
    $layout = Get-ShareLayout $share

    $entries = @(Get-SharePrincipalEntries $share $layout)
    if ($entries.Count -eq 0) {
        Write-Warn 'Aucun utilisateur/groupe (hors Administrateurs/Systeme) ne possede de droit explicite sur ce partage.'
        return
    }

    Write-Host ''
    Write-Host ('  {0,4} {1,-45} {2,-15} {3}' -f 'No', 'Compte', 'Partage (SMB)', 'NTFS')
    for ($i = 0; $i -lt $entries.Count; $i++) {
        $e = $entries[$i]
        $ntfs = if ($e.Ntfs) { 'oui' } else { 'non' }
        $smb  = if ($e.SmbRights) { $e.SmbRights } elseif ($e.SmbNames.Count) { 'oui' } else { '-' }
        Write-Host ('  [{0,2}] {1,-45} {2,-15} {3}' -f ($i + 1), $e.Name, $smb, $ntfs)
    }
    $idx = @(Read-Selection -Max $entries.Count)
    if ($idx.Count -eq 0) { return }
    $targets = @($idx | ForEach-Object { $entries[$_ - 1] })

    Write-Info ('Comptes a retirer : ' + (($targets | ForEach-Object { $_.Name }) -join ', '))
    if (-not (Read-YesNo "Confirmer le retrait de l'acces au partage $($share.Name) ?")) { return }

    foreach ($t in $targets) {
        try {
            Revoke-SharePrincipal -Share $share -Layout $layout -Entry $t
            Write-Ok "$($t.Name) retire du partage $($share.Name)."
        } catch {
            Write-Err "$($t.Name) : $($_.Exception.Message)"
        }
    }
}

# =====================================================================
#  5. Creer un nouveau partage
# =====================================================================

# Get-SmbShare -Name leve une erreur quand le partage n'existe pas, meme avec
# -ErrorAction SilentlyContinue lorsque $ErrorActionPreference vaut Stop
# (cmdlet CIM) : on liste donc tous les partages et on filtre sur le nom.
function Test-ShareExists([string]$Name) {
    return [bool](@(Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -ieq $Name }).Count)
}

function Test-ShareName([string]$Name) {
    if ($Name.Length -gt 80) { return 'Nom trop long (80 caracteres maximum).' }
    if ($Name -match '[\\/\[\]:|<>+=;,?*"]') { return 'Le nom contient un caractere interdit : \ / [ ] : | < > + = ; , ? * "' }
    if ($Name -match '[\. ]$') { return 'Le nom ne doit pas se terminer par un point ou un espace.' }
    if ($Name -match '[^\x20-\x7E]') { return 'Utilisez uniquement des caracteres sans accent.' }
    if (Test-ShareExists $Name) { return "Le partage '$Name' existe deja." }
    return $null
}

function New-StructuredShare {
    if (-not (Assert-Ad)) { return }
    Write-Title 'Creer un nouveau partage'

    # Nom
    while ($true) {
        $name = Read-Text -Prompt 'Nom du partage (Entree pour annuler)' -AllowEmpty
        if (-not $name) { return }
        $problem = Test-ShareName $name
        if (-not $problem) { break }
        Write-Warn $problem
    }

    # Emplacement
    while ($true) {
        $base = Read-Text -Prompt 'Dossier parent' -Default $script:BasePath
        $valid = $false
        try {
            if ([System.IO.Path]::IsPathRooted($base) -and $base -match '^[A-Za-z]:\\') {
                $drive = $base.Substring(0, 3)
                if (Test-Path -LiteralPath $drive) { $valid = $true }
                else { Write-Warn "Le lecteur $drive n'existe pas." }
            } else {
                Write-Warn 'Indiquez un chemin local complet (ex: D:\Partages).'
            }
        } catch {
            Write-Warn "Chemin invalide : $($_.Exception.Message)"
        }
        if ($valid) { break }
    }
    $root = Join-Path $base $name
    if (Test-Path -LiteralPath $root) {
        Write-Warn "Le dossier $root existe deja : ses droits NTFS seront remplaces."
        if (-not (Read-YesNo 'Continuer ?')) { return }
    }

    $description = Read-Text -Prompt 'Description (facultatif)' -AllowEmpty

    # Comptes
    $members = @(Select-AdPrincipals -Title "Membres du partage (lecture/modif sur $CommonFolderName, depot seul sur $DepotFolderName)")
    $managers = @()
    if (Read-YesNo "Ajouter des gestionnaires du dossier $DepotFolderName (lecture/modification) ?") {
        $managers = @(Select-AdPrincipals -Title "Gestionnaires du dossier $DepotFolderName")
    }
    $managerSids = @($managers | ForEach-Object { $_.Sid.Value })
    $members = @($members | Where-Object { $managerSids -notcontains $_.Sid.Value })
    if ($members.Count -eq 0 -and $managers.Count -eq 0) {
        Write-Warn 'Aucun compte selectionne : seuls les administrateurs auront acces (ajout possible plus tard).'
    }

    # Recapitulatif
    Write-Host ''
    Write-Host '--- Recapitulatif ---' -ForegroundColor Cyan
    Write-Info "Partage       : $name"
    Write-Info "Dossier       : $root"
    Write-Info "  |- $CommonFolderName : lecture/modification pour les membres et gestionnaires"
    Write-Info "  |- $DepotFolderName  : depot sans lecture (membres), lecture/modification (gestionnaires)"
    Write-Info ('Membres       : ' + $(if ($members) { ($members | ForEach-Object { $_.Name }) -join ', ' } else { '(aucun)' }))
    Write-Info ('Gestionnaires : ' + $(if ($managers) { ($managers | ForEach-Object { $_.Name }) -join ', ' } else { '(aucun)' }))
    if (-not (Read-YesNo 'Creer le partage ?' $true)) { return }

    $commun = Join-Path $root $CommonFolderName
    $depot  = Join-Path $root $DepotFolderName

    $step = 'creation des dossiers'
    try {
        # Dossiers
        foreach ($d in @($root, $commun, $depot)) {
            if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
        }
        Write-Ok 'Dossiers crees.'

        $step = 'application des droits NTFS'

        # Racine : heritage coupe, Administrateurs + Systeme en controle total
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        $acl.AddAccessRule((New-FsRule $script:SidAdmins $script:Rights.FullControl $script:Inherit.Both $script:Propagate.None))
        $acl.AddAccessRule((New-FsRule $script:SidSystem $script:Rights.FullControl $script:Inherit.Both $script:Propagate.None))
        Set-FolderAcl $root $acl

        # Sous-dossiers : heritage actif, aucun droit explicite
        foreach ($d in @($commun, $depot)) {
            $acl = Get-FolderAcl $d
            $acl.SetAccessRuleProtection($false, $false)
            foreach ($r in @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))) {
                [void]$acl.RemoveAccessRuleSpecific($r)
            }
            Set-FolderAcl $d $acl
        }

        # Depot : le proprietaire d'un fichier depose ne recupere pas de droit de lecture implicite
        Add-FolderRules $depot @(Get-OwnerRightsRule)
        Write-Ok 'Droits NTFS de base appliques.'

        # Partage SMB
        $step = 'creation du partage SMB'
        $params = @{
            Name                  = $name
            Path                  = $root
            FullAccess            = Get-AdminsName
            # Pas d'enumeration basee sur l'acces : elle masquerait le dossier Depot,
            # sur lequel les membres n'ont volontairement pas le droit de lister.
            FolderEnumerationMode = 'Unrestricted'
            ErrorAction           = 'Stop'
        }
        if ($description) { $params.Description = $description }
        New-SmbShare @params | Out-Null
        $share = @(Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -ieq $name }) | Select-Object -First 1
        if (-not $share) { throw "le partage '$name' est introuvable apres sa creation." }
        Write-Ok "Partage \\$($script:Ctx.Fqdn)\$name cree."
    } catch {
        Write-Err "Echec lors de l'etape '$step' : $($_.Exception.Message)"
        Write-Err "Le partage '$name' n'a pas ete cree completement. Corrigez le probleme puis relancez la creation."
        return
    }

    $layout = Get-ShareLayout $share
    foreach ($p in $members) {
        try {
            Grant-SharePrincipal -Share $share -Layout $layout -Principal $p -Role Standard
            Write-Ok "Membre ajoute : $($p.Name)"
        } catch { Write-Err "$($p.Name) : $($_.Exception.Message)" }
    }
    foreach ($p in $managers) {
        try {
            Grant-SharePrincipal -Share $share -Layout $layout -Principal $p -Role Gestionnaire
            Write-Ok "Gestionnaire du depot ajoute : $($p.Name)"
        } catch { Write-Err "$($p.Name) : $($_.Exception.Message)" }
    }

    if ($script:Ctx.GpOk -and (Read-YesNo 'Creer maintenant une GPO de mappage pour ce partage ?')) {
        New-DriveMapGpo -Share $share
    }
}

# =====================================================================
#  7. Mise a jour des droits du dossier Depot (partages existants)
# =====================================================================

function Repair-DepotRights {
    Write-Title "Mettre a jour les droits du dossier $DepotFolderName"
    Write-Info "Corrige les partages crees avec une version precedente du script :"
    Write-Info "  - desactive l'enumeration basee sur l'acces (qui masquait le dossier $DepotFolderName)"
    Write-Info "  - retire aux membres le droit d'ecrire dans les fichiers deposes par les autres"
    Write-Info "  - seul l'auteur d'un depot garde l'ecriture/suppression de son propre fichier"

    $share = Select-Share
    if (-not $share) { return }
    $layout = Get-ShareLayout $share
    if (-not $layout.Structured) {
        Write-Err "Le partage '$($share.Name)' ne contient pas les dossiers $CommonFolderName/$DepotFolderName."
        return
    }
    if (-not (Read-YesNo "Mettre a jour le partage $($share.Name) ?" $true)) { return }

    Set-SmbShare -Name $share.Name -FolderEnumerationMode Unrestricted -Force -ErrorAction Stop
    Write-Ok "Enumeration basee sur l'acces desactivee : le dossier $DepotFolderName est visible."

    $sync = [int]$FSR::Synchronize
    $oldFiles = [int]$script:Rights.DepotFiles -band (-bnot $sync)
    $acl = Get-FolderAcl $layout.Depot
    $removed = 0
    foreach ($r in @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))) {
        $v = [int]$r.FileSystemRights -band (-bnot $sync)
        if ($r.IdentityReference.Value -eq $script:SidOwnerRights.Value -or $v -eq $oldFiles) {
            [void]$acl.RemoveAccessRuleSpecific($r)
            if ($r.IdentityReference.Value -ne $script:SidOwnerRights.Value) { $removed++ }
        }
    }
    $acl.AddAccessRule((Get-OwnerRightsRule))
    Set-FolderAcl $layout.Depot $acl
    Write-Ok "$removed droit(s) d'ecriture sur les fichiers des autres retire(s), droits de l'auteur mis a jour."
}

# =====================================================================
#  6. GPO de mappage
# =====================================================================

function Get-ExistingDriveMaps {
    $list = New-Object System.Collections.Generic.List[object]
    $srv = $script:Ctx.Server
    $dns = $script:Ctx.DomainDns
    foreach ($g in @(Get-GPO -All -Domain $dns -Server $srv -ErrorAction Stop)) {
        $file = "\\$srv\SYSVOL\$dns\Policies\{$($g.Id)}\User\Preferences\Drives\Drives.xml"
        if (-not (Test-Path -LiteralPath $file)) { continue }
        try {
            $xml = New-Object System.Xml.XmlDocument
            $xml.Load($file)
        } catch {
            Write-Warn "Lecture impossible de $file : $($_.Exception.Message)"
            continue
        }
        foreach ($d in @($xml.SelectNodes('//Drive'))) {
            $p = $d.SelectSingleNode('Properties')
            if (-not $p) { continue }
            $list.Add([pscustomobject]@{
                GpoName  = $g.DisplayName
                GpoId    = $g.Id
                Path     = $p.GetAttribute('path')
                Letter   = $p.GetAttribute('letter').ToUpper()
                Action   = $p.GetAttribute('action')
                Disabled = ($d.GetAttribute('disabled') -eq '1')
            })
        }
    }
    return @($list | Where-Object { $_.Action -ne 'D' -and -not $_.Disabled })
}

function Test-UncTargetsShare([string]$Path, [string]$ShareName) {
    if ($Path -notmatch '^\\\\([^\\]+)\\([^\\]+)') { return $false }
    $hostName = $Matches[1].Split('.')[0]
    $shareInPath = $Matches[2]
    return ($hostName -ieq $env:COMPUTERNAME -and $shareInPath -ieq $ShareName)
}

function Get-ShareMappings($ShareName, $Maps) {
    return @($Maps | Where-Object { Test-UncTargetsShare $_.Path $ShareName })
}

function Get-ParentDn([string]$Dn) {
    if ($Dn -match '^(?:[^,\\]|\\.)+,(.*)$') { return $Matches[1] }
    return $Dn
}

function Format-DnPath([string]$Dn) {
    $parts = [regex]::Split($Dn, '(?<!\\),') | Where-Object { $_ -match '^OU=' } | ForEach-Object { $_.Substring(3) }
    $parts = @($parts)
    [array]::Reverse($parts)
    if ($parts.Count -eq 0) { return "$($script:Ctx.DomainDns) (racine du domaine)" }
    return "$($script:Ctx.DomainDns)/" + ($parts -join '/')
}

# Navigation simple dans les OU : numero pour descendre, P pour remonter,
# R pour rechercher une OU par son nom, V pour valider l'emplacement courant.
function Select-OrganizationalUnit {
    $root = $script:Ctx.DomainDN
    $current = $root
    while ($true) {
        try {
            $children = @(Get-ADOrganizationalUnit -SearchBase $current -SearchScope OneLevel -Filter * `
                            -Server $script:Ctx.Server -ErrorAction Stop | Sort-Object Name)
        } catch {
            Write-Err "Lecture des OU impossible : $($_.Exception.Message)"
            $children = @()
        }
        Write-Host ''
        Write-Host "Emplacement actuel : $(Format-DnPath $current)" -ForegroundColor Cyan
        if ($children.Count -eq 0) { Write-Info '  (aucune sous-OU)' }
        for ($i = 0; $i -lt $children.Count; $i++) {
            Write-Host ('  [{0,2}] {1}' -f ($i + 1), $children[$i].Name)
        }
        Write-Info '  Numero = entrer dans l''OU | V = lier la GPO ici | P = remonter | R = rechercher | A = annuler'
        $choice = Read-Host 'Choix'
        if ($null -eq $choice) { $choice = '' }
        $choice = $choice.Trim()

        if ($choice -match '^\d+$') {
            $n = [int]$choice
            if ($n -ge 1 -and $n -le $children.Count) { $current = $children[$n - 1].DistinguishedName }
            else { Write-Warn "Numero invalide (1 a $($children.Count))." }
        }
        elseif ($choice -match '^v$') { return $current }
        elseif ($choice -match '^p$') {
            if ($current -ieq $root) { Write-Warn 'Vous etes deja a la racine du domaine.' }
            else { $current = Get-ParentDn $current }
        }
        elseif ($choice -match '^r$') {
            $term = Read-Text -Prompt 'Nom (ou partie du nom) de l''OU' -AllowEmpty
            if (-not $term) { continue }
            $value = ConvertTo-LdapValue $term
            if ($value -notmatch '\*') { $value = "*$value*" }
            try {
                $found = @(Get-ADOrganizationalUnit -LDAPFilter "(name=$value)" -SearchBase $root -SearchScope Subtree `
                              -Server $script:Ctx.Server -ResultSetSize 51 -ErrorAction Stop | Sort-Object DistinguishedName)
            } catch {
                Write-Err "Recherche impossible : $($_.Exception.Message)"
                continue
            }
            if ($found.Count -eq 0) { Write-Warn "Aucune OU ne correspond a '$term'."; continue }
            if ($found.Count -gt 50) { Write-Warn 'Plus de 50 resultats, affinez la recherche.'; $found = $found[0..49] }
            for ($i = 0; $i -lt $found.Count; $i++) {
                Write-Host ('  [{0,2}] {1}' -f ($i + 1), (Format-DnPath $found[$i].DistinguishedName))
            }
            $idx = @(Read-Selection -Max $found.Count -Single)
            if ($idx.Count -eq 1) { $current = $found[$idx[0] - 1].DistinguishedName }
        }
        elseif ($choice -match '^a$') { return $null }
        elseif ($choice) { Write-Warn 'Choix invalide.' }
    }
}

function Read-DriveLetter($Maps) {
    $used = @($Maps | ForEach-Object { $_.Letter } | Where-Object { $_ } | Select-Object -Unique)
    $candidates = 'S','T','U','V','W','X','Y','Z','R','Q','P','O','N','M','L','K','J','I','H','G'
    $suggest = $candidates | Where-Object { $used -notcontains $_ } | Select-Object -First 1
    if ($used) { Write-Info ('Lettres deja utilisees par des GPO : ' + (($used | Sort-Object) -join ', ')) }
    while ($true) {
        $letter = Read-Text -Prompt 'Lettre de lecteur' -Default $suggest
        $letter = $letter.TrimEnd(':').ToUpper()
        if ($letter -notmatch '^[D-Z]$') {
            Write-Warn 'Entrez une seule lettre entre D et Z.'
            continue
        }
        if ($used -contains $letter) {
            $who = ($Maps | Where-Object { $_.Letter -eq $letter } | ForEach-Object { $_.GpoName } | Select-Object -Unique) -join ', '
            Write-Warn "La lettre $letter est deja utilisee par : $who"
            if (-not (Read-YesNo 'Utiliser quand meme cette lettre ?')) { continue }
        }
        return $letter
    }
}

function Get-ShareDomainPrincipals($Share) {
    $layout = Get-ShareLayout $Share
    $result = New-Object System.Collections.Generic.List[object]
    foreach ($e in (Get-SharePrincipalEntries $Share $layout)) {
        if (-not $e.Sid -or -not $e.Sid.Value.StartsWith("$($script:Ctx.DomainSid)-")) { continue }
        $p = Get-AdPrincipalBySid $e.Sid
        if ($p) { $result.Add($p) }
    }
    return $result.ToArray()
}

function Select-FilterPrincipals($Share) {
    Write-Host ''
    Write-Info 'Filtrage de securite de la GPO :'
    Write-Info '  [1] Uniquement les utilisateurs/groupes ayant acces au partage'
    Write-Info '  [2] Rechercher les utilisateurs/groupes cibles'
    Write-Info '  [Entree] Aucun filtrage (tous les utilisateurs des OU ciblees)'
    while ($true) {
        $c = Read-Host 'Choix'
        if ($null -eq $c) { $c = '' }
        switch ($c.Trim()) {
            '' { return @() }
            '1' {
                $list = @(Get-ShareDomainPrincipals $Share)
                if ($list.Count -eq 0) {
                    Write-Warn 'Aucun compte du domaine n''a de droit explicite sur ce partage.'
                    continue
                }
                for ($i = 0; $i -lt $list.Count; $i++) {
                    Write-Host ('  [{0,2}] {1,-12} {2}' -f ($i + 1), $list[$i].Type, $list[$i].Name)
                }
                $idx = @(Read-Selection -Max $list.Count)
                if ($idx.Count -eq 0) { continue }
                return @($idx | ForEach-Object { $list[$_ - 1] })
            }
            '2' {
                $list = @(Select-AdPrincipals -Title 'Cibles de la GPO')
                if ($list.Count -eq 0) { continue }
                return $list
            }
            default { Write-Warn 'Choix invalide (1, 2 ou Entree).' }
        }
    }
}

function New-DrivesXml([string]$Letter, [string]$Unc, [string]$Label) {
    $esc = { param($s) [System.Security.SecurityElement]::Escape($s) }
    $now = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $uid = [guid]::NewGuid().ToString('B').ToUpper()
    return '<?xml version="1.0" encoding="utf-8"?>' + "`r`n" +
        '<Drives clsid="{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}">' +
        '<Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="' + $Letter + ':" status="' + $Letter + ':" ' +
        'image="2" changed="' + $now + '" uid="' + $uid + '" bypassErrors="1">' +
        '<Properties action="U" thisDrive="NOCHANGE" allDrives="NOCHANGE" userName="" ' +
        'path="' + (& $esc $Unc) + '" label="' + (& $esc $Label) + '" persistent="1" useLetter="1" letter="' + $Letter + '"/>' +
        '</Drive></Drives>' + "`r`n"
}

function New-DriveMapGpo {
    param($Share)

    if (-not (Assert-Ad)) { return }
    if (-not $script:Ctx.GpOk) {
        Write-Err 'Le module GroupPolicy est requis (Install-WindowsFeature GPMC).'
        return
    }
    Write-Title 'Creer une GPO de mappage de lecteur'

    $srv = $script:Ctx.Server
    $dns = $script:Ctx.DomainDns
    Write-Info 'Analyse des mappages existants dans les GPO du domaine...'
    $maps = @(Get-ExistingDriveMaps)

    if (-not $Share) {
        $all = @(Get-ManagedShares)
        $free = @($all | Where-Object { @(Get-ShareMappings $_.Name $maps).Count -eq 0 })
        $mapped = @($all | Where-Object { @(Get-ShareMappings $_.Name $maps).Count -gt 0 })
        if ($mapped.Count -gt 0) {
            Write-Host "`nPartages deja mappes (non proposes) :" -ForegroundColor Cyan
            foreach ($s in $mapped) {
                $m = Get-ShareMappings $s.Name $maps
                $info = ($m | ForEach-Object { "$($_.Letter): via '$($_.GpoName)'" } | Select-Object -Unique) -join ', '
                Write-Info "  $($s.Name) -> $info"
            }
        }
        if ($free.Count -eq 0) {
            Write-Warn 'Tous les partages sont deja mappes par une GPO.'
            return
        }
        $Share = Select-Share -Shares $free -Title 'Partages non mappes'
        if (-not $Share) { return }
    } else {
        $m = @(Get-ShareMappings $Share.Name $maps)
        if ($m.Count -gt 0) {
            $info = ($m | ForEach-Object { "$($_.Letter): via '$($_.GpoName)'" } | Select-Object -Unique) -join ', '
            Write-Warn "Le partage $($Share.Name) est deja mappe : $info"
            return
        }
    }

    $unc = "\\$($script:Ctx.Fqdn)\$($Share.Name)"
    Write-Info "Chemin mappe : $unc"
    $letter = Read-DriveLetter $maps
    $label = Read-Text -Prompt 'Nom affiche du lecteur' -Default $Share.Name

    $gpoName = $null
    while (-not $gpoName) {
        $candidate = Read-Text -Prompt 'Nom de la GPO' -Default "MAP - $($Share.Name) ($letter)"
        $exists = $null
        try { $exists = Get-GPO -Name $candidate -Domain $dns -Server $srv -ErrorAction Stop } catch { }
        if ($exists) { Write-Warn "Une GPO nommee '$candidate' existe deja."; continue }
        $gpoName = $candidate
    }

    Write-Host "`nChoisissez l'OU ou lier la GPO (les utilisateurs de cette OU recevront le lecteur)." -ForegroundColor Cyan
    $ou = Select-OrganizationalUnit
    if (-not $ou) { Write-Warn 'Operation annulee.'; return }

    $filter = @(Select-FilterPrincipals $Share)

    Write-Host ''
    Write-Host '--- Recapitulatif ---' -ForegroundColor Cyan
    Write-Info "GPO       : $gpoName"
    Write-Info "Lecteur   : ${letter}: -> $unc ($label)"
    Write-Info "Liee a    : $(Format-DnPath $ou)"
    Write-Info ('Filtrage  : ' + $(if ($filter) { ($filter | ForEach-Object { $_.Name }) -join ', ' } else { 'aucun (utilisateurs authentifies)' }))
    if (-not (Read-YesNo 'Creer la GPO ?' $true)) { return }

    $gpo = $null
    try {
        $gpo = New-GPO -Name $gpoName -Domain $dns -Server $srv -Comment "Mappage $letter`: vers $unc (cree par Gestion-Partages.ps1)" -ErrorAction Stop
        $guid = $gpo.Id.ToString('B').ToUpper()
        $gpoPath = "\\$srv\SYSVOL\$dns\Policies\$guid"
        Write-Ok "GPO creee : $gpoName $guid"

        $tries = 0
        while (-not (Test-Path -LiteralPath $gpoPath) -and $tries -lt 15) { Start-Sleep -Seconds 1; $tries++ }
        if (-not (Test-Path -LiteralPath $gpoPath)) { throw "Dossier SYSVOL de la GPO introuvable : $gpoPath" }

        # Preferences > Mappages de lecteurs
        $drivesDir = Join-Path $gpoPath 'User\Preferences\Drives'
        New-Item -ItemType Directory -Path $drivesDir -Force | Out-Null
        $xmlContent = New-DrivesXml -Letter $letter -Unc $unc -Label $label
        [System.IO.File]::WriteAllText((Join-Path $drivesDir 'Drives.xml'), $xmlContent, (New-Object System.Text.UTF8Encoding($true)))

        # Version (partie utilisateur = 16 bits de poids fort) + extensions cote client
        $gpoDn = "CN=$guid,CN=Policies,CN=System,$($script:Ctx.DomainDN)"
        $adGpo = Get-ADObject -Identity $gpoDn -Server $srv -Properties versionNumber -ErrorAction Stop
        $newVersion = [int]$adGpo.versionNumber + 65536

        $gptIni = Join-Path $gpoPath 'GPT.INI'
        $lines = @()
        if (Test-Path -LiteralPath $gptIni) { $lines = @(Get-Content -LiteralPath $gptIni) }
        if (-not ($lines -match '^\[General\]')) { $lines = @('[General]') + $lines }
        if ($lines -match '^Version=') {
            $lines = $lines | ForEach-Object { if ($_ -match '^Version=') { "Version=$newVersion" } else { $_ } }
        } else {
            $lines += "Version=$newVersion"
        }
        [System.IO.File]::WriteAllText($gptIni, (($lines -join "`r`n") + "`r`n"), [System.Text.Encoding]::ASCII)

        Set-ADObject -Identity $gpoDn -Server $srv -ErrorAction Stop -Replace @{
            versionNumber          = $newVersion
            gPCUserExtensionNames  = $script:DriveMapsExtensions
        }
        # La partie ordinateur n'est pas utilisee
        try {
            $gpoObj = Get-GPO -Guid $gpo.Id -Domain $dns -Server $srv -ErrorAction Stop
            $gpoObj.GpoStatus = 'ComputerSettingsDisabled'
        } catch {
            Write-Warn "Impossible de desactiver la partie ordinateur de la GPO : $($_.Exception.Message)"
        }
        Write-Ok "Mappage $letter`: -> $unc ajoute a la GPO."

        New-GPLink -Guid $gpo.Id -Target $ou -Domain $dns -Server $srv -LinkEnabled Yes -ErrorAction Stop | Out-Null
        Write-Ok "GPO liee a $(Format-DnPath $ou)."
    } catch {
        Write-Err "Echec de la creation de la GPO : $($_.Exception.Message)"
        if ($gpo) {
            try {
                Remove-GPO -Guid $gpo.Id -Domain $dns -Server $srv -ErrorAction Stop
                Write-Warn 'La GPO incomplete a ete supprimee.'
            } catch {
                Write-Warn "Supprimez manuellement la GPO '$gpoName' : $($_.Exception.Message)"
            }
        }
        return
    }

    # Filtrage de securite (facultatif)
    if ($filter.Count -gt 0) {
        $applied = 0
        foreach ($p in $filter) {
            $targetType = switch ($p.Class) { 'group' { 'Group' } 'computer' { 'Computer' } default { 'User' } }
            $done = $false
            $lastError = ''
            foreach ($n in @($p.Sam, $p.Name) | Where-Object { $_ } | Select-Object -Unique) {
                try {
                    Set-GPPermission -Guid $gpo.Id -TargetName $n -TargetType $targetType -PermissionLevel GpoApply `
                        -DomainName $dns -Server $srv -ErrorAction Stop | Out-Null
                    $done = $true
                    break
                } catch {
                    $lastError = $_.Exception.Message
                }
            }
            if ($done) { $applied++; Write-Ok "Filtrage : $($p.Name) peut appliquer la GPO." }
            else { Write-Err "Filtrage : $($p.Name) : $lastError" }
        }
        if ($applied -gt 0) {
            try {
                $authName = (ConvertTo-AccountName $script:SidAuthUsers).Split('\')[-1]
                Set-GPPermission -Guid $gpo.Id -TargetName $authName -TargetType Group -PermissionLevel GpoRead -Replace `
                    -DomainName $dns -Server $srv -ErrorAction Stop | Out-Null
                Write-Ok "'$authName' passe en lecture seule sur la GPO (n'applique plus la GPO)."
            } catch {
                Write-Warn "Impossible de modifier les droits des utilisateurs authentifies : $($_.Exception.Message)"
                Write-Warn 'La GPO s''applique donc toujours a tous les utilisateurs de l''OU.'
            }
        } else {
            Write-Warn 'Aucun filtrage applique : la GPO s''applique a tous les utilisateurs de l''OU.'
        }
    }

    Write-Host ''
    Write-Ok "Termine. Le lecteur ${letter}: sera connecte a la prochaine ouverture de session (ou apres gpupdate /force)."
}

# =====================================================================
#  Menu principal
# =====================================================================

function Show-Menu {
    Write-Title "Gestion des partages - $env:COMPUTERNAME"
    if ($script:Ctx.AdOk) { Write-Info "Domaine : $($script:Ctx.DomainDns) (DC : $($script:Ctx.Server))" }
    Write-Host ''
    Write-Host '  [1] Lister les partages existants'
    Write-Host '  [2] Ajouter des utilisateurs/groupes a un partage'
    Write-Host "  [3] Ajouter un gestionnaire du dossier $DepotFolderName (lecture/modification)"
    Write-Host "  [4] Retirer l'acces a un partage"
    Write-Host '  [5] Creer un nouveau partage'
    Write-Host '  [6] Creer une GPO de mappage pour un partage non mappe'
    Write-Host "  [7] Mettre a jour les droits du dossier $DepotFolderName d'un partage existant"
    Write-Host '  [Q] Quitter'
    Write-Host ''
}

try {
    Initialize-Environment
} catch {
    Write-Err "Initialisation impossible : $($_.Exception.Message)"
    return
}

while ($true) {
    Show-Menu
    $choice = Read-Host 'Votre choix'
    if ($null -eq $choice) { $choice = '' }
    $choice = $choice.Trim()
    if ($choice -match '^(q|quitter)$') { break }

    try {
        switch ($choice) {
            '1' { Show-Shares }
            '2' { Add-ShareAccess -Role Standard }
            '3' { Add-ShareAccess -Role Gestionnaire }
            '4' { Remove-ShareAccess }
            '5' { New-StructuredShare }
            '6' { New-DriveMapGpo }
            '7' { Repair-DepotRights }
            default { Write-Warn 'Choix invalide.' }
        }
    } catch {
        Write-Err $_.Exception.Message
    }
    Wait-Return
}
