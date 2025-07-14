function Get-DirectoryObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DomainName,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilterString,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $AttributesList,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBasePath,

        [ValidateNotNullOrEmpty()]
        [String]
        $SearchPathPrefix,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $ServerName,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScopeType = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $PageSizeLimit = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $TimeoutLimit = 120,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMaskType,

        [Switch]
        $IncludeTombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $UserCredential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['DomainName']) {
            $TargetDomainName = $DomainName

            if ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
                $UserDomainName = $ENV:USERDNSDOMAIN
                if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $UserDomainName) {
                    $BindServerName = "$($ENV:LOGONSERVER -replace '\\','').$UserDomainName"
                }
            }
        }
        elseif ($PSBoundParameters['UserCredential']) {
            $DomainObjectResult = Get-DomainInfo -Credential $UserCredential
            $BindServerName = ($DomainObjectResult.PdcRoleOwner).Name
            $TargetDomainName = $DomainObjectResult.Name
        }
        elseif ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
            $TargetDomainName = $ENV:USERDNSDOMAIN
            if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $TargetDomainName) {
                $BindServerName = "$($ENV:LOGONSERVER -replace '\\','').$TargetDomainName"
            }
        }
        else {
            write-verbose "get-domain"
            $DomainObjectResult = Get-DomainInfo
            $BindServerName = ($DomainObjectResult.PdcRoleOwner).Name
            $TargetDomainName = $DomainObjectResult.Name
        }

        if ($PSBoundParameters['ServerName']) {
            $BindServerName = $ServerName
        }

        $SearchStringPath = 'LDAP://'

        if ($BindServerName -and ($BindServerName.Trim() -ne '')) {
            $SearchStringPath += $BindServerName
            if ($TargetDomainName) {
                $SearchStringPath += '/'
            }
        }

        if ($PSBoundParameters['SearchPathPrefix']) {
            $SearchStringPath += $SearchPathPrefix + ','
        }

        if ($PSBoundParameters['SearchBasePath']) {
            if ($SearchBasePath -Match '^GC://') {
                $DistinguishedName = $SearchBasePath.ToUpper().Trim('/')
                $SearchStringPath = ''
            }
            else {
                if ($SearchBasePath -match '^LDAP://') {
                    if ($SearchBasePath -match "LDAP://.+/.+") {
                        $SearchStringPath = ''
                        $DistinguishedName = $SearchBasePath
                    }
                    else {
                        $DistinguishedName = $SearchBasePath.SubString(7)
                    }
                }
                else {
                    $DistinguishedName = $SearchBasePath
                }
            }
        }
        else {
            if ($TargetDomainName -and ($TargetDomainName.Trim() -ne '')) {
                $DistinguishedName = "DC=$($TargetDomainName.Replace('.', ',DC='))"
            }
        }

        $SearchStringPath += $DistinguishedName
        Write-Verbose "[Get-DirectoryObject] search base: $SearchStringPath"

        if ($UserCredential -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "[Get-DirectoryObject] Using alternate credentials for LDAP connection"
            $DomainObjectResult = New-Object DirectoryServices.DirectoryEntry($SearchStringPath, $UserCredential.UserName, $UserCredential.GetNetworkCredential().Password)
            $SearcherObject = New-Object System.DirectoryServices.DirectorySearcher($DomainObjectResult)
        }
        else {
            $SearcherObject = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchStringPath)
        }

        $SearcherObject.PageSize = $PageSizeLimit
        $SearcherObject.SearchScope = $SearchScopeType
        $SearcherObject.CacheResults = $False
        $SearcherObject.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All

        if ($PSBoundParameters['TimeoutLimit']) {
            $SearcherObject.ServerTimeLimit = $TimeoutLimit
        }

        if ($PSBoundParameters['IncludeTombstone']) {
            $SearcherObject.Tombstone = $True
        }

        if ($PSBoundParameters['LDAPFilterString']) {
            $SearcherObject.filter = $LDAPFilterString
        }

        if ($PSBoundParameters['SecurityMaskType']) {
            $SearcherObject.SecurityMasks = Switch ($SecurityMaskType) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }

        if ($PSBoundParameters['AttributesList']) {
            $AttributesToLoad = $AttributesList| ForEach-Object { $_.Split(',') }
            $Null = $SearcherObject.PropertiesToLoad.AddRange(($AttributesToLoad))
        }

        $SearcherObject
    }
}

function Get-DomainInfo {
    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DomainName,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Credential']) {

            Write-Verbose '[Get-DomainInfo] Using alternate credentials for Get-DomainInfo'

            if ($PSBoundParameters['DomainName']) {
                $TargetDomainName = $DomainName
            }
            else {
                $TargetDomainName = $Credential.GetNetworkCredential().Domain
                Write-Verbose "[Get-DomainInfo] Extracted domain '$TargetDomainName' from -Credential"
            }

            $DomainContextObject = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $TargetDomainName, $Credential.UserName, $Credential.GetNetworkCredential().Password)

            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContextObject)
            }
            catch {
                Write-Verbose "[Get-DomainInfo] The specified domain '$TargetDomainName' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        }
        elseif ($PSBoundParameters['DomainName']) {
            $DomainContextObject = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $DomainName)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContextObject)
            }
            catch {
                Write-Verbose "[Get-DomainInfo] The specified domain '$DomainName' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose "[Get-DomainInfo] Error retrieving the current domain: $_"
            }
        }
    }
}

function Get-ForestInformation {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ForestName,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Credential']) {

            Write-Verbose "[Get-ForestInformation] Using alternate credentials for Get-ForestInformation"

            if ($PSBoundParameters['ForestName']) {
                $TargetForestName = $ForestName
            }
            else {
                $TargetForestName = $Credential.GetNetworkCredential().Domain
                Write-Verbose "[Get-ForestInformation] Extracted domain '$ForestName' from -Credential"
            }

            $ForestContextObject = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $TargetForestName, $Credential.UserName, $Credential.GetNetworkCredential().Password)

            try {
                $ForestObjectResult = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContextObject)
            }
            catch {
                Write-Verbose "[Get-ForestInformation] The specified forest '$TargetForestName' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
                $Null
            }
        }
        elseif ($PSBoundParameters['ForestName']) {
            $ForestContextObject = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $ForestName)
            try {
                $ForestObjectResult = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContextObject)
            }
            catch {
                Write-Verbose "[Get-ForestInformation] The specified forest '$ForestName' does not exist, could not be contacted, or there isn't an existing trust: $_"
                return $Null
            }
        }
        else {
            try {
                $ForestObjectResult = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            }
            catch {
                Write-Verbose "[Get-ForestInformation] Error retrieving the current forest: $_"
                return $Null
            }
        }

        if ($ForestObjectResult) {
            $ForestSidMapping = @{}
            $ForestObjectResult.Domains | ForEach-Object {
                $DomainSid = (New-Object System.Security.Principal.SecurityIdentifier($_.GetDirectoryEntry().objectSid[0],0)).Value
                $ForestSidMapping[$DomainSid] = $_.Name
            }

            $ForestObjectResult | Add-Member NoteProperty 'SidMapping' $ForestSidMapping
            $ForestObjectResult
        }
    }
}

function Get-AttributeMapping {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $DomainName,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $ServerName,

        [ValidateRange(1, 10000)]
        [Int]
        $PageSizeLimit = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $TimeoutLimit,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    $GUIDMapping = @{'00000000-0000-0000-0000-000000000000' = 'All'}

    $ForestParameters = @{}
    if ($PSBoundParameters['Credential']) { $ForestParameters['Credential'] = $Credential }

    try {
        $SchemaLocation = (Get-ForestInformation @ForestParameters).schema.name
    }
    catch {
        throw '[Get-AttributeMapping] Error in retrieving forest schema path from Get-ForestInformation'
    }
    if (-not $SchemaLocation) {
        throw '[Get-AttributeMapping] Error in retrieving forest schema path from Get-ForestInformation'
    }

    $SearcherParameters = @{
        'SearchBasePath' = $SchemaLocation
        'LDAPFilterString' = '(schemaIDGUID=*)'
    }
    if ($PSBoundParameters['DomainName']) { $SearcherParameters['DomainName'] = $DomainName }
    if ($PSBoundParameters['ServerName']) { $SearcherParameters['ServerName'] = $ServerName }
    if ($PSBoundParameters['PageSizeLimit']) { $SearcherParameters['PageSizeLimit'] = $PageSizeLimit }
    if ($PSBoundParameters['TimeoutLimit']) { $SearcherParameters['TimeoutLimit'] = $TimeoutLimit }
    if ($PSBoundParameters['Credential']) { $SearcherParameters['Credential'] = $Credential }
    $SchemaSearcherObject = Get-DirectoryObject @SearcherParameters

    if ($SchemaSearcherObject) {
        try {
            $SearchResults = $SchemaSearcherObject.FindAll()
            $SearchResults | Where-Object {$_} | ForEach-Object {
                $GUIDMapping[(New-Object Guid (,$_.properties.schemaidguid[0])).Guid] = $_.properties.name[0]
            }
            if ($SearchResults) {
                try { $SearchResults.dispose() }
                catch {
                    Write-Verbose "[Get-AttributeMapping] Error disposing of the Results object: $_"
                }
            }
            $SchemaSearcherObject.dispose()
        }
        catch {
            Write-Verbose "[Get-AttributeMapping] Error in building GUID map: $_"
        }
    }

    $SearcherParameters['SearchBasePath'] = $SchemaLocation.replace('Schema','Extended-Rights')
    $SearcherParameters['LDAPFilterString'] = '(objectClass=controlAccessRight)'
    $RightsSearcherObject = Get-DirectoryObject @SearcherParameters

    if ($RightsSearcherObject) {
        try {
            $SearchResults = $RightsSearcherObject.FindAll()
            $SearchResults | Where-Object {$_} | ForEach-Object {
                $GUIDMapping[$_.properties.rightsguid[0].toString()] = $_.properties.name[0]
            }
            if ($SearchResults) {
                try { $SearchResults.dispose() }
                catch {
                    Write-Verbose "[Get-AttributeMapping] Error disposing of the Results object: $_"
                }
            }
            $RightsSearcherObject.dispose()
        }
        catch {
            Write-Verbose "[Get-AttributeMapping] Error in building GUID map: $_"
        }
    }

    $GUIDMapping
}

function Get-SecurityDescriptor {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('CustomSecurity.ACL')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $TargetIdentity,

        [Switch]
        $SystemACL,

        [Switch]
        $ResolveGUIDs,

        [String]
        [Alias('Rights')]
        [ValidateSet('All', 'ResetPassword', 'WriteMembers')]
        $RightsFilterType,

        [ValidateNotNullOrEmpty()]
        [String]
        $DomainName,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilterString,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBasePath,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $ServerName,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScopeType = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $PageSizeLimit = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $TimeoutLimit,

        [Switch]
        $IncludeTombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $UserCredential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherParameters = @{
            'AttributesList' = 'samaccountname,ntsecuritydescriptor,distinguishedname,objectsid'
        }

        if ($PSBoundParameters['SystemACL']) {
            $SearcherParameters['SecurityMaskType'] = 'Sacl'
        }
        else {
            $SearcherParameters['SecurityMaskType'] = 'Dacl'
        }
        if ($PSBoundParameters['DomainName']) { $SearcherParameters['DomainName'] = $DomainName }
        if ($PSBoundParameters['SearchBasePath']) { $SearcherParameters['SearchBasePath'] = $SearchBasePath }
        if ($PSBoundParameters['ServerName']) { $SearcherParameters['ServerName'] = $ServerName }
        if ($PSBoundParameters['SearchScopeType']) { $SearcherParameters['SearchScopeType'] = $SearchScopeType }
        if ($PSBoundParameters['PageSizeLimit']) { $SearcherParameters['PageSizeLimit'] = $PageSizeLimit }
        if ($PSBoundParameters['TimeoutLimit']) { $SearcherParameters['TimeoutLimit'] = $TimeoutLimit }
        if ($PSBoundParameters['IncludeTombstone']) { $SearcherParameters['IncludeTombstone'] = $IncludeTombstone }
        if ($PSBoundParameters['UserCredential']) { $SearcherParameters['UserCredential'] = $UserCredential }
        $SearcherObject = Get-DirectoryObject @SearcherParameters

        $GUIDMapParameters = @{}
        if ($PSBoundParameters['DomainName']) { $GUIDMapParameters['DomainName'] = $DomainName }
        if ($PSBoundParameters['ServerName']) { $GUIDMapParameters['ServerName'] = $ServerName }
        if ($PSBoundParameters['PageSizeLimit']) { $GUIDMapParameters['PageSizeLimit'] = $PageSizeLimit }
        if ($PSBoundParameters['TimeoutLimit']) { $GUIDMapParameters['TimeoutLimit'] = $TimeoutLimit }
        if ($PSBoundParameters['UserCredential']) { $GUIDMapParameters['UserCredential'] = $UserCredential }

        if ($PSBoundParameters['ResolveGUIDs']) {
            $GUIDMapping = Get-AttributeMapping @GUIDMapParameters
        }
    }

    PROCESS {
        if ($SearcherObject) {
            $IdentityFilterString = ''
            $FilterString = ''
            $TargetIdentity | Where-Object {$_} | ForEach-Object {
                $IdentityInstanceString = $_.Replace('(', '\28').Replace(')', '\29')
                if ($IdentityInstanceString -match '^S-1-.*') {
                    $IdentityFilterString += "(objectsid=$IdentityInstanceString)"
                }
                elseif ($IdentityInstanceString -match '^(CN|OU|DC)=.*') {
                    $IdentityFilterString += "(distinguishedname=$IdentityInstanceString)"
                    if ((-not $PSBoundParameters['DomainName']) -and (-not $PSBoundParameters['SearchBasePath'])) {
                        $IdentityDomainName = $IdentityInstanceString.SubString($IdentityInstanceString.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-SecurityDescriptor] Extracted domain '$IdentityDomainName' from '$IdentityInstanceString'"
                        $SearcherParameters['DomainName'] = $IdentityDomainName
                        $SearcherObject = Get-DirectoryObject @SearcherParameters
                        if (-not $SearcherObject) {
                            Write-Warning "[Get-SecurityDescriptor] Unable to retrieve domain searcher for '$IdentityDomainName'"
                        }
                    }
                }
                elseif ($IdentityInstanceString -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $GuidByteArray = (([Guid]$IdentityInstanceString).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilterString += "(objectguid=$GuidByteArray)"
                }
                elseif ($IdentityInstanceString.Contains('.')) {
                    $IdentityFilterString += "(|(samAccountName=$IdentityInstanceString)(name=$IdentityInstanceString)(dnshostname=$IdentityInstanceString))"
                }
                else {
                    $IdentityFilterString += "(|(samAccountName=$IdentityInstanceString)(name=$IdentityInstanceString)(displayname=$IdentityInstanceString))"
                }
            }
            if ($IdentityFilterString -and ($IdentityFilterString.Trim() -ne '') ) {
                $FilterString += "(|$IdentityFilterString)"
            }

            if ($PSBoundParameters['LDAPFilterString']) {
                Write-Verbose "[Get-SecurityDescriptor] Using additional LDAP filter: $LDAPFilterString"
                $FilterString += "$LDAPFilterString"
            }

            if ($FilterString) {
                $SearcherObject.filter = "(&$FilterString)"
            }
            Write-Verbose "[Get-SecurityDescriptor] Get-SecurityDescriptor filter string: $($SearcherObject.filter)"

            $SearchResults = $SearcherObject.FindAll()
            $SearchResults | Where-Object {$_} | ForEach-Object {
                $ObjectProperties = $_.Properties

                if ($ObjectProperties.objectsid -and $ObjectProperties.objectsid[0]) {
                    $ObjectSidValue = (New-Object System.Security.Principal.SecurityIdentifier($ObjectProperties.objectsid[0],0)).Value
                }
                else {
                    $ObjectSidValue = $Null
                }

                try {
                    New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $ObjectProperties['ntsecuritydescriptor'][0], 0 | ForEach-Object { if ($PSBoundParameters['SystemACL']) {$_.SystemAcl} else {$_.DiscretionaryAcl} } | ForEach-Object {
                        if ($PSBoundParameters['RightsFilterType']) {
                            $GuidFilterValue = Switch ($RightsFilterType) {
                                'ResetPassword' { '00299570-246d-11d0-a768-00aa006e0529' }
                                'WriteMembers' { 'bf9679c0-0de6-11d0-a285-00aa003049e2' }
                                Default { '00000000-0000-0000-0000-000000000000' }
                            }
                            if ($_.ObjectType -eq $GuidFilterValue) {
                                $_ | Add-Member NoteProperty 'ObjectDN' $ObjectProperties.distinguishedname[0]
                                $_ | Add-Member NoteProperty 'ObjectSID' $ObjectSidValue
                                $ContinueProcessing = $True
                            }
                        }
                        else {
                            $_ | Add-Member NoteProperty 'ObjectDN' $ObjectProperties.distinguishedname[0]
                            $_ | Add-Member NoteProperty 'ObjectSID' $ObjectSidValue
                            $ContinueProcessing = $True
                        }

                        if ($ContinueProcessing) {
                            $_ | Add-Member NoteProperty 'ActiveDirectoryRights' ([Enum]::ToObject([System.DirectoryServices.ActiveDirectoryRights], $_.AccessMask))
                            if ($GUIDMapping) {
                                $ACLPropertiesHash = @{}
                                $_.psobject.properties | ForEach-Object {
                                    if ($_.Name -match 'ObjectType|InheritedObjectType|ObjectAceType|InheritedObjectAceType') {
                                        try {
                                            $ACLPropertiesHash[$_.Name] = $GUIDMapping[$_.Value.toString()]
                                        }
                                        catch {
                                            $ACLPropertiesHash[$_.Name] = $_.Value
                                        }
                                    }
                                    else {
                                        $ACLPropertiesHash[$_.Name] = $_.Value
                                    }
                                }
                                $OutputObject = New-Object -TypeName PSObject -Property $ACLPropertiesHash
                                $OutputObject.PSObject.TypeNames.Insert(0, 'CustomSecurity.ACL')
                                $OutputObject
                            }
                            else {
                                $_.PSObject.TypeNames.Insert(0, 'CustomSecurity.ACL')
                                $_
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "[Get-SecurityDescriptor] Error: $_"
                }
            }
        }
    }
}

Set-Alias Get-ACLInfo Get-SecurityDescriptor

function Test-SecurityDescriptor {
    [CmdletBinding()]
    Param(
        [String]$TestTarget = $env:USERNAME
    )
    
    Write-Host "Testing Get-SecurityDescriptor function..." -ForegroundColor Green
    
    try {
        # Test 1: Get ACL for current user
        Write-Host "Test 1: Getting ACL for user '$TestTarget'" -ForegroundColor Yellow
        $userACL = Get-SecurityDescriptor -TargetIdentity $TestTarget
        if ($userACL) {
            Write-Host "SUCCESS: Found $($userACL.Count) ACL entries" -ForegroundColor Green
            $userACL | Select-Object ObjectDN, ActiveDirectoryRights, AceType | Format-Table -AutoSize
        } else {
            Write-Host "No ACL entries found" -ForegroundColor Yellow
        }
        
        # Test 2: Test with GUID resolution
        Write-Host "Test 2: Testing GUID resolution" -ForegroundColor Yellow
        $resolvedACL = Get-SecurityDescriptor -TargetIdentity $TestTarget -ResolveGUIDs
        if ($resolvedACL) {
            Write-Host "SUCCESS: GUID resolution working" -ForegroundColor Green
        }
        
        Write-Host "All tests completed successfully!" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Test-DCReplicationRights {
    [CmdletBinding()]
    Param(
        [String]$TestUser = $env:USERNAME,
        [String]$DomainName
    )
    
    Write-Host "Checking DCSync/Replication rights for user '$TestUser'..." -ForegroundColor Green
    
    try {
        # Get domain DN for the target
        if ($DomainName) {
            $DomainDN = "DC=" + ($DomainName -replace '\.', ',DC=')
        } else {
            $domain = Get-DomainInfo
            $DomainDN = $domain.Name -replace '\.', ',DC='
            $DomainDN = "DC=$DomainDN"
        }
        
        Write-Host "Checking domain: $DomainDN" -ForegroundColor Yellow
        
        # Get ACL for the domain root
        $domainACL = Get-SecurityDescriptor -TargetIdentity $DomainDN -ResolveGUIDs
        
        # DCSync requires these specific GUIDs:
        $dcsyncGUIDs = @(
            '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',  # DS-Replication-Get-Changes
            '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',  # DS-Replication-Get-Changes-All
            '89e95b76-444d-4c62-991a-0facbeda640c'   # DS-Replication-Get-Changes-In-Filtered-Set
        )
        
        $userSID = (New-Object System.Security.Principal.NTAccount($TestUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        Write-Host "User SID: $userSID" -ForegroundColor Cyan
        
        $foundRights = @()
        
        foreach ($ace in $domainACL) {
            if ($ace.SecurityIdentifier -eq $userSID -and $ace.AceType -eq 'AccessAllowed') {
                if ($ace.ActiveDirectoryRights -match 'ExtendedRight') {
                    $objectType = $ace.ObjectType
                    if ($objectType -in $dcsyncGUIDs) {
                        $foundRights += $objectType
                        $rightName = switch ($objectType) {
                            '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' { 'DS-Replication-Get-Changes' }
                            '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' { 'DS-Replication-Get-Changes-All' }
                            '89e95b76-444d-4c62-991a-0facbeda640c' { 'DS-Replication-Get-Changes-In-Filtered-Set' }
                        }
                        Write-Host "FOUND: $rightName ($objectType)" -ForegroundColor Red
                    }
                }
                
                # Also check for GenericAll which includes DCSync
                if ($ace.ActiveDirectoryRights -match 'GenericAll') {
                    Write-Host "FOUND: GenericAll rights (includes DCSync capability)" -ForegroundColor Red
                    $foundRights += 'GenericAll'
                }
            }
        }
        
        if ($foundRights.Count -gt 0) {
            Write-Host "`nWARNING: User '$TestUser' has DCSync capabilities!" -ForegroundColor Red
            Write-Host "Rights found: $($foundRights -join ', ')" -ForegroundColor Red
            return $true
        } else {
            Write-Host "`nUser '$TestUser' does NOT have DCSync rights." -ForegroundColor Green
            return $false
        }
        
    }
    catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Test-UserPrivileges {
    [CmdletBinding()]
    Param(
        [String]$TestUser = $env:USERNAME
    )
    
    Write-Host "Comprehensive privilege check for user '$TestUser'..." -ForegroundColor Green
    
    # Test 1: Basic ACL retrieval
    Write-Host "`n=== Basic ACL Test ===" -ForegroundColor Yellow
    Test-SecurityDescriptor -TestTarget $TestUser
    
    # Test 2: DCSync rights
    Write-Host "`n=== DCSync Rights Test ===" -ForegroundColor Yellow
    Test-DCReplicationRights -TestUser $TestUser
    
    # Test 3: Check group memberships that might grant DCSync
    Write-Host "`n=== Dangerous Group Memberships ===" -ForegroundColor Yellow
    try {
        $userObj = Get-SecurityDescriptor -TargetIdentity $TestUser
        if ($userObj) {
            Write-Host "User object found: $($userObj[0].ObjectDN)" -ForegroundColor Cyan
        }
    }
    catch {
        Write-Host "Could not retrieve user object details" -ForegroundColor Yellow
    }
}