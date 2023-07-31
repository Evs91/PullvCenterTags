import-module sqlserver 
################################################
# Input Parameters
################################################
$vcenterUsername = $args[0]
$vcenterPassword = $args[1]
$vcenterFQDN = $args[2]
$SQLServer = $args[3]

################################################
# SQLServerSetup
################################################

$ServerInstance = $SQLServer
$DatabaseName = "VMwareInventoryData"


$Date = Get-Date
$Date = $Date.ToString("yyyy-MM-dd HH:mm:ss")

################################################
# Adding certificate exception to prevent API errors
################################################
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


################################################
# Functions
################################################
function Get-VCSession {
param(
    [string]$vCenter,
    [string]$vCenterUser,
    [string]$vCenterPassword,
    [string]$vCenterURL
    )
    $vCenterBaseAuthURL = 'https://'+$vcenterURL+"/rest/com/vmware/cis/"
    $vCenterBaseURL = 'https://'+$vcenterURL+"/rest/vcenter/"
    $vCenterSessionURL = 'https://'+$vcenterURL+"/rest/com/vmware/cis/session"
    $auth = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($vCenterUser+":"+$vCenterPassword))
    ###Generate Header with Auth hash###
    $head = @{
        'Authorization' = "Basic $auth"
        }
    $Type = "application/json"
    $AuthResponse = Invoke-WebRequest -Uri $vCenterSessionURL -Method Post -Headers $head -UseBasicParsing
    ### Get session token from json response
    $token = (ConvertFrom-Json $AuthResponse.Content).value
    $session = @{'vmware-api-session-id' = $token}
    ### return session key,value as result of function
    return $session.Values
}

function Get-VMInventory {
param(
    [string]$AuthToken,
    [string]$vCenterURL
    )
    $vCenterInventoryURL = 'https://'+$vcenterURL+"/rest/vcenter/vm"
    $head = @{'vmware-api-session-id' = $AuthToken}
    $inventory = Invoke-WebRequest -Uri $vCenterInventoryURL -Method Get -Headers $head -UseBasicParsing
    ## returns VM inventory of vCenter
    return (ConvertFrom-Json $inventory.Content)
    ###content returned has: 
    # memory_size_MiB :  [int]    2048
    # VM ID           :  [string] vm-#####
    # Name            :  [string]  CORPXXXX
    # power_state     :  [string] POWERED_ON, POWERED_OFF, SUSPENDED
    # cpu count       :  [int]    1
    ###############
}

function Get-VMIdentity {
param(
    [string]$vmname,
    [string]$vCenterURL,
    [string]$AuthToken
    )
    $vCenterInventoryURL = 'https://'+$vcenterURL+"/rest/vcenter/vm/"
    $vCenterVMIdentityURL = $vCenterInventoryURL + $vmname + "/guest/identity"
    $head = @{'vmware-api-session-id' = $AuthToken}
    $response = Invoke-WebRequest -Uri $vCenterVMIdentityURL -Method Get -Headers $head -TimeoutSec 3 -UseBasicParsing
    return (ConvertFrom-Json $response.Content)
    ###content returned has: 
    # full_name  : @{args=System.Object[]; default_message=CentOS 8 (64-bit); id=vmsg.guestos.centos8_64Guest.label}
    # name       : CENTOS_8_64
    # ip_address : 10.201.100.226
    # family     : LINUX
    # host_name  : host.domain.com
    ###############
}

function Get-VMHardwareData {
param(
    [string]$vmname,
    [string]$AuthToken,
    [string]$vCenterURL,
    [Parameter(Mandatory)]
    [ValidateSet('memory','cpu', 'disk', 'ethernet','boot', 'cdrom')]
    [string]$HardwareType
    )
    $vCenterInventoryURL = 'https://'+$vcenterURL+"/rest/vcenter/vm/"
    $vCenterVMIdentityURL = $vCenterInventoryURL + $vmname + "/hardware/" + $HardwareType
    $head = @{'vmware-api-session-id' = $AuthToken}
    $response = Invoke-WebRequest -Uri $vCenterVMIdentityURL -Method Get -Headers $head -TimeoutSec 5 -UseBasicParsing
    return (ConvertFrom-Json $response.Content)
    #lots of data returned based on what hardware type is chosen. just go look at the responses to find the data. 
    #Will document later
}

function Get-VMSummaryData {
param(
    [Parameter(Mandatory)]
    [string]$vmname,
    [string]$vCenterURL,
    [string]$AuthToken
    )
    $vCenterVMSummaryURL = 'https://'+$vcenterURL+"/rest/vcenter/vm/" +$vmname
    $head = @{'vmware-api-session-id' = $AuthToken}
    $response = Invoke-WebRequest -Uri $vCenterVMSummaryURL -Method Get -Headers $head -UseBasicParsing
    return (ConvertFrom-Json $response.Content)
    #lots of data returned based on what hardware type is chosen. just go look at the responses to find the data. 
    #Will document later
}

function Get-VMSummaryDataFilter {
param(
    [Parameter(Mandatory)]
    [string]$AuthToken,
    [string]$filter
    )
    $vCenterVMSummaryURL = 'https://'+$vcenterURL+"/rest/vcenter/vm?filter.vms="+$filter
    $head = @{'vmware-api-session-id' = $AuthToken}
    $response = Invoke-WebRequest -Uri $vCenterVMSummaryURL -Method Get -Headers $head -UseBasicParsing
    return (ConvertFrom-Json $response.Content)
    #lots of data returned based on what hardware type is chosen. just go look at the responses to find the data. 
    #Will document later
}

function Get-vCenterTags {
param(
    [string]$AuthToken,
    [string]$vCenterURL
    )
    $vCenterTagURL = 'https://'+$vcenterURL+"/rest/com/vmware/cis/tagging/tag"
    $head = @{'vmware-api-session-id' = $AuthToken}
    $response = Invoke-WebRequest -Uri $vCenterTagURL -Method Get -Headers $head -UseBasicParsing
    return (convertFrom-Json $response.Content)
}

function Get-vCenterTagsDescription {
param(
    [string]$AuthToken,
    [string]$vCenterURL,
    [string]$tagUUID
    )
    $vCenterTagURL = 'https://'+$vcenterURL+"/rest/com/vmware/cis/tagging/tag/id:"+$tagUUID
    $head = @{'vmware-api-session-id' = $AuthToken}
    $response = Invoke-WebRequest -Uri $vCenterTagURL -Method Get -Headers $head -UseBasicParsing
    return (convertFrom-Json $response.Content)
}

function Get-vCenterTagsCategories {
param(
    [string]$AuthToken,
    [string]$vCenterURL
    )
    $vCenterTagURL = 'https://'+$vcenterURL+"/rest/com/vmware/cis/tagging/category"
    $head = @{'vmware-api-session-id' = $AuthToken}
    $response = Invoke-WebRequest -Uri $vCenterTagURL -Method Get -Headers $head -UseBasicParsing
    return (convertFrom-Json $response.Content)

    ## returns UUIDS of categories
}

function Get-vCenterTagsCategoriesDescription {
param(
    [string]$AuthToken,
    [string]$vCenterURL,
    [string]$tagUUID
    )
    $vCenterTagURL = 'https://'+$vcenterURL+"/rest/com/vmware/cis/tagging/category/id:"+$tagUUID
    $head = @{'vmware-api-session-id' = $AuthToken}
    $response = Invoke-WebRequest -Uri $vCenterTagURL -Method Get -Headers $head -UseBasicParsing
    return (convertFrom-Json $response.Content)

    ###returns associable types (list)
    ## name == name of category
    ### description
    ### UUID
    ### Used by (list)
    ### cardinality
}

function Get-vCenterTagObjects {
param(
    [string]$AuthToken,
    [string]$vCenterURL,
    [string]$tagUUID
    )
    $type = "application/json"
    $head = @{'vmware-api-session-id' = $AuthToken}
    $vCenterTagURL = 'https://'+$vcenterURL+"/rest/com/vmware/cis/tagging/tag-association?~action=list-attached-objects-on-tags"
    $TagJSON = 
    "{
    ""tag_ids"": [
    ""$tagUUID""
    ]
    }"
    
  
  $response = Invoke-RestMethod -Method Post -Body $TagJSON -Uri $vCenterTagURL -Headers $head -ContentType $type
  return $response

  ## tag_id urn:vmomi:InventoryServiceTag:634412e7-1f9f-40e1-bdda-f93aded71a15:GLOBAL
  ### vm obj id = $response.value.object_ids.id

}

function Get-vCenterNetworks {
param(
    [string]$AuthToken,
    [string]$vCenterURL
    )
    $vCenterNetworkURL = 'https://'+$vcenterURL+"/rest/vcenter/network"
    $head = @{'vmware-api-session-id' = $AuthToken}
    $response = Invoke-WebRequest -Uri $vCenterNetworkURL -Method Get -Headers $head -UseBasicParsing
    return (convertFrom-Json $response.Content)

}

function Get-vCenterNetworksLookup {
param(
    [string]$AuthToken,
    [string]$vCenterURL,
    [string]$networkID
    )
    $vCenterNetworkURL = 'https://'+$vcenterURL+'/rest/vcenter/network?filter.networks.1='+$networkID
    $head = @{'vmware-api-session-id' = $AuthToken}
    $response = Invoke-WebRequest -Uri $vCenterNetworkURL -Method Get -Headers $head -UseBasicParsing
    return (convertFrom-Json $response.Content)

}



#####################
##Null Arrays
#####################


$TagArray = @()
$CategoryArray = @()
$VMTagArray = @()
$VMArray = @()
$VMNetworkArray = @()

##########################################
##Get Session Auth Token 
##########################################

$session = Get-VCSession -vCenterURL $vcenterFQDN -vCenterUser $vcenterUsername -vCenterPassword $vcenterPassword

##########################################
## Get Tag Categories from vCenter 
##########################################

$CategoryResponse = Get-vCenterTagsCategories -AuthToken $session -vCenterURL $vcenterFQDN
foreach ($Category in $CategoryResponse.value) {
    $response = Get-vCenterTagsCategoriesDescription -AuthToken $session -tagUUID $Category -vCenterURL $vcenterFQDN
    $CategoryArrayLine = New-Object PSObject
    $TagCategoryName = $response.value.name
    $TagCategoryID = $response.value.id
    $TagCategoryDescription = $response.value.description
    $CategoryArrayLine | Add-Member NoteProperty -Name "Name" -Value $TagCategoryName
    $CategoryArrayLine | Add-Member NoteProperty -Name "ID" -Value $TagCategoryID
    $CategoryArrayLine | Add-Member NoteProperty -Name "Description" -Value $TagCategoryDescription
    $CategoryArray += $CategoryArrayLine
    }

#########################################################
## Get Tags from vCenter and join with assoc categories
#########################################################

$TagResponse = Get-vCenterTags -AuthToken $session -vCenterURL $vcenterFQDN
ForEach ($TagID in $TagResponse.value) {
    $response = Get-vCenterTagsDescription -AuthToken $session -tagUUID $TagID -vCenterURL $vcenterFQDN
    $TagName = $response.value.name
    $TagID = $response.value.id
    $TagCategoryName = $CategoryArray | Where-Object {$_.ID -eq $TagCategoryID} | Select -ExpandProperty Name
    $TagCategoryID = $response.value.category_id
    $TagArrayLine = New-Object PSObject
    $TagArrayLine | Add-Member -MemberType NoteProperty -Name "Name" -Value "$TagName"
    $TagArrayLine | Add-Member -MemberType NoteProperty -Name "ID" -Value "$TagID"
    $TagArrayLine | Add-Member -MemberType NoteProperty -Name "CategoryName" -Value "$TagCategoryName"
    $TagArrayLine | Add-Member -MemberType NoteProperty -Name "CategoryID" -Value "$TagCategoryID"
    $TagArray += $TagArrayLine
}

#########################################################
## Generate UUID Translation Table and insert to SQL
#########################################################

foreach ($VMLine in $TagArray) {
    $VMObjectTagUUID = $VMLine.ID
    $VMCategoryUUID = $VMLine.CategoryID
    $VMObjResponse = Get-vCenterTagObjects -AuthToken $session -tagUUID $VMLine.ID -vCenterURL $vcenterFQDN
    
    foreach ($VMObjectID in $VMObjResponse.value.object_ids) {
        $VMUUID = $VMObjectID.id
        $VMTagArrayLine = New-Object PSObject
        $VMTagArrayLine | Add-Member -MemberType NoteProperty -Name "VMUUID" -Value $VMUUID
        $VMTagArrayLine | Add-Member -MemberType NoteProperty -Name "TagUUID" -Value $VMObjectTagUUID
        $VMTagArrayLine | Add-Member -MemberType NoteProperty -Name "CategoryUUID" -Value $VMCategoryUUID
##Tag is required to except ":" in UUIDs
        $VMTagInsert = @"
'$VMUUID', '$VMCategoryUUID', '$VMObjectTagUUID', '$Date'
"@

$VMObjSqlQuery = "INSERT INTO VMwareInventoryData.dbo.VM_Obj_Tags (VM_UUID, Category_UUID, Tag_UUID, TimeStamp) VALUES ($VMTagInsert)"
    $params = @{'server'= $ServerInstance ;'Database'=$DatabaseName}
    $FileInfo = Invoke-Sqlcmd @params -Query $VMObjSqlQuery 
        }

    }

#########################################################
## Generate Category Table and insert to SQL
#########################################################

foreach ($CategoryLine in $CategoryArray) {
    $CatName = $CategoryLine.Name
    $CatUUID = $CategoryLine.ID
    $CatDesc = $CategoryLine.Description

##Tag is required to except ":" in UUIDs
    $CatInsert =  @"
'$CatUUID', '$CatName', '$CatDesc', '$Date'
"@

    $CatSqlQuery = "INSERT INTO VMwareInventoryData.dbo.VM_Categories (VM_Category_UUID, VM_Category_Name, VM_Category_Description, TimeStamp) VALUES ($CatInsert)"

    $params = @{'server'= $ServerInstance ;'Database'=$DatabaseName}
    $FileInfo = Invoke-Sqlcmd @params -Query $CatSqlQuery 

}

#########################################################
## Generate Tag Table and insert to SQL
#########################################################

ForEach ($TagLine in $TagArray) {
    $VM_Tag_Name = $TagLine.name
    $VM_Tag_UUID = $TagLine.id
 $TagInsert =  @"
'$VM_Tag_Name', '$VM_Tag_UUID', '$Date'
"@     
    $TagSqlQuery = "INSERT INTO VMwareInventoryData.dbo.VM_Tags (VM_Tag_Name, VM_Tag_UUID, TimeStamp ) VALUES ($TagInsert)"
    $params = @{'server'= $ServerInstance ;'Database'=$DatabaseName}
    $FileInfo = Invoke-Sqlcmd @params -Query $TagSqlQuery
}

#########################################################
## Generate VM Inventory Data Table and insert to SQL
#########################################################

$VMinventory = Get-VMInventory -AuthToken $session -vCenterURL $vcenterFQDN

foreach ($VMItem in $VMinventory) {
    $vmobjIDs = $VMItem.value
    foreach ($VM in $vmobjIDs) {
        $response = Get-VMSummaryData -AuthToken $session -vmname $vm.vm -vCenterURL $vcenterFQDN
        $ident_response = Get-VMIdentity -AuthToken $session -vmname $vm.vm -vCenterURL $vcenterFQDN
        $VM_UUID = $vm.vm
        $VM_Name = $response.value.name
        $OS_Type = $response.value.guest_OS
        $PowerState = $response.value.power_state
        $CPU_Count = $response.value.cpu.count
        $CPU_Cores_Per_Socket = $response.value.cpu.cores_per_socket
        $CPU_HotAddEnabled = $response.value.cpu.hot_add_enabled
        $CPU_Hot_Add_Enabled = $response.value.cpu.hot_remove_enabled
        $Ram_Size_Mib = $response.value.memory.size_MiB
        $RAM_Hot_Add_Enabled = $response.value.memory.hot_add_enabled
        $BIOSType= $response.value.boot.type
        $IP_Addr = $ident_response.value.ip_address
        $FQDN = $ident_response.value.host_name
        $OS_Fam = $ident_response.value.family
        $VM_Hardware_Version = $response.value.hardware.version
        $vCenter_Location = $vcenterFQDN
        $VMArrayLine = New-Object PSObject
        $VMArrayLine | Add-Member -MemberType NoteProperty -Name "VM_UUID" -Value $VM_UUID
        $VMArrayLine | Add-Member -MemberType NoteProperty -Name "VM_Name" -Value $VM_Name
        $VMArrayLine | Add-Member -MemberType NoteProperty -Name "OS_Type" -Value $OS_Type
        $VMArrayLine | Add-Member -MemberType NoteProperty -Name "PowerState" -Value $PowerState
        $VMArrayLine | Add-Member -MemberType NoteProperty -Name "CPU_Count" -Value $CPU_Count
        $VMArrayLine | Add-Member -MemberType NoteProperty -Name "CPU_Cores_Per_Socket" -Value $CPU_Cores_Per_Socket
        $VMArrayLine | Add-Member -MemberType NoteProperty -Name "CPU_Hot_Add_Enabled" -Value $CPU_Hot_Add_Enabled
        $VMArrayLine | Add-Member -MemberType NoteProperty -Name "CPU_Hot_Remove_Enabled" -Value $CPU_Hot_Remove_Enabled
        $VMArrayLine | Add-Member -MemberType NoteProperty -Name "Ram_Size_Mib" -Value $Ram_Size_Mib
        $VMArrayLine | Add-Member -MemberType NoteProperty -Name "RAM_Hot_Add_Enabled" -Value $RAM_Hot_Add_Enabled
        $VMArrayLine | Add-Member -MemberType NoteProperty -Name "BIOSType" -Value $BIOSType
        $VMArrayLine | Add-Member -MemberType NoteProperty -Name "IPAddr" -Value $IP_Addr
        $VMArrayLine | Add-Member -MemberType NoteProperty -Name "HostName" -Value $FQDN
        $VMArrayLine | Add-Member -MemberType NoteProperty -Name "OS_Fam" -Value $OS_Fam
        $VMArrayLine | Add-Member -MemberType NoteProperty -Name "VM_Hardware_Version" -Value $VM_Hardware_Version
        $VMArrayLine | Add-Member -MemberType NoteProperty -Name "vCenter_Location" -Value $vCenter_Location
        $VMArray += $VMArrayLine
$TagInsert =  @"
'$OS_Type', '$IP_Addr', '$OS_Fam', '$FQDN', '$CPU_Hot_Remove_Enabled', '$CPU_Count', '$CPU_Hot_Add_Enabled', '$CPU_Cores_Per_Socket', '$RAM_Size_MiB', '$RAM_Hot_Add_Enabled', '$VM_UUID', '$VM_Name', '$BIOSType','$PowerState', '$VM_Hardware_Version', '$vCenter_Location', '$Date'
"@   
    $VMSqlQuery = "INSERT INTO VMwareInventoryData.dbo.VM_Data (OS_Type, IP_Addr, OS_Fam, FQDN, CPU_Hot_Remove_Enabled, CPU_Count, CPU_Hot_Add_Enabled, CPU_Cores_Per_Socket, RAM_Size_MiB, RAM_Hot_Add_Enabled, VM_UUID, VM_Name, BIOSType, PowerState, VM_Hardware_Version, vCenter_Location, TimeStamp ) VALUES ($TagInsert)"
  #  Write-Host $VMSqlQuery
    $params = @{'server'= $ServerInstance ;'Database'=$DatabaseName}
    $FileInfo = Invoke-Sqlcmd @params -Query $VMSqlQuery
    }
}

#########################################################
## Generate NIC / PortGroup Table and insert to SQL
#########################################################

$VMinventory = Get-VMInventory -AuthToken $session -vCenterURL $vcenterFQDN

foreach ($VMItem in $VMinventory) {
    $vmobjIDs = $VMItem.value
    foreach ($VM in $vmobjIDs) {
        $response = Get-VMSummaryData -AuthToken $session -vmname $vm.vm -vCenterURL $vcenterFQDN
        $VM_UUID = $vm.vm
        $nicArray = $response.value.nics
        foreach ($nicItem in $nicArray) {
            $NIC_start_connected = $nicItem.value.start_connected
            $NIC_macaddress = $nicItem.value.mac_address
            $NIC_allow_guest_control = $nicItem.value.allow_guest_control
            $NIC_State = $nicItem.value.state
            $NIC_Type = $nicItem.value.type
            $NIC_VLAN_UUID = $nicItem.value.backing.network
            $NIC_Portgroup_Type = $nicItem.value.backing.type
            $NIC_dswitch_UUID = $nicItem.value.backing.distributed_switch_uuid
            $NIC_Standard_Switch_Name = $nicItem.value.backing.network_name
            $NICresponse = Get-vCenterNetworksLookup -AuthToken $session -networkID $NIC_VLAN_UUID -vCenterURL $vcenterFQDN
            $NIC_VLAN_Network_Description = $NICresponse.value.name
            $VMNetworkArrayLine = New-Object PSObject
            $VMNetworkArrayLine | Add-Member -MemberType NoteProperty -Name "VM_UUID" -Value $VM_UUID
            $VMNetworkArrayLine | Add-Member -MemberType NoteProperty -Name "NIC_start_connected" -Value $NIC_start_connected
            $VMNetworkArrayLine | Add-Member -MemberType NoteProperty -Name "NIC_macaddress" -Value $NIC_macaddress
            $VMNetworkArrayLine | Add-Member -MemberType NoteProperty -Name "NIC_allow_guest_control" -Value $NIC_allow_guest_control
            $VMNetworkArrayLine | Add-Member -MemberType NoteProperty -Name "NIC_State" -Value $NIC_State
            $VMNetworkArrayLine | Add-Member -MemberType NoteProperty -Name "NIC_Type" -Value $NIC_Type
            $VMNetworkArrayLine | Add-Member -MemberType NoteProperty -Name "NIC_VLAN_UUID" -Value $NIC_VLAN_UUID
            $VMNetworkArrayLine | Add-Member -MemberType NoteProperty -Name "NIC_Portgroup_Type" -Value $NIC_Portgroup_Type
            $VMNetworkArrayLine | Add-Member -MemberType NoteProperty -Name "NIC_dswitch_UUID" -Value $NIC_dswitch_UUID
            $VMNetworkArrayLine | Add-Member -MemberType NoteProperty -Name "NIC_Standard_Switch_Name" -Value $NIC_Standard_Switch_Name
            $VMNetworkArrayLine | Add-Member -MemberType NoteProperty -Name "NIC_VLAN_Network_Description" -Value $NIC_VLAN_Network_Description
            $VMNetworkArray += $VMNetworkArrayLine
            $TagInsert =  @"
'$VM_UUID', '$NIC_start_connected', '$NIC_macaddress', '$NIC_allow_guest_control', '$NIC_State', '$NIC_Type', '$NIC_VLAN_UUID', '$NIC_Portgroup_Type', '$NIC_dswitch_UUID', '$NIC_Standard_Switch_Name', '$NIC_VLAN_Network_Description', '$Date'
"@   
    $VMNICSqlQuery = "INSERT INTO VMwareInventoryData.dbo.VM_NIC_Data (VM_UUID, NIC_start_connected, NIC_macaddress, NIC_allow_guest_control, NIC_State, NIC_Type, NIC_VLAN_UUID, NIC_Portgroup_Type, NIC_dswitch_UUID, NIC_Standard_Switch_Name, NIC_VLAN_Network_Description, TimeStamp ) VALUES ($TagInsert)"
    $params = @{'server'= $ServerInstance ;'Database'=$DatabaseName}
    $FileInfo = Invoke-Sqlcmd @params -Query $VMNICSqlQuery
            }
    }
}
