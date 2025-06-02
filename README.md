# building Microsoft Sentinal dashboard with honeypot's event data

## Goal of the project
The aim of this project is to build a proactive threat‐monitoring system in Azure that uses a simulated “honeypot” VM to attract unauthorized login attempts.  
I will provision an Azure VM, configure Resource Groups and Network Security Group (NSG) rules, and deploy log analytics workspace, and Microsoft Sentinel to centralize logging, and monitoring.  
A PowerShell script on the VM will continuously scan for failed sign‐in events, extract the attacker’s IP address, and call an external API to determine geographic location.  
All relevant data such as timestamp, attempted username, IP, and location will be ingested into Sentinel for alerting and visualization.  
Within Sentinel, these IPs will be plotted on a world map, enabling quick identification of attack origin and helping defenders respond more effectively.  

## workflow of the project

## setting up azure account and subscription
For this project, I have created new microsoft azure account with student subscription plans which provides me a free access to lots of services with 100USD free credit. 
## create resource group and virtual network
To settingup this project I created resource group and virtual network which is building block of the whole project.
* settingup resource group
  > go to Resource groups in microsoft azure portal  
  > create new resource group  
  > select subscription plan, name the resource group as ``` SOC_center ```, selected ``` East US 2 ``` location  
  > finally, review and create the resource group
<img width="1512" alt="image" src="https://github.com/user-attachments/assets/e605df00-9f84-4a84-8b2c-32f5f6ca111b" />

* settingup virtual network  
  > go to Virtual networks in microsoft azure portal  
  > select subscription, resource group which just i created, the same location as resource group and name it as ``` vnet-soc-center ```  
  > review the security services for the network  
  > configure different subnets with different ip ranges  
  > finally review and create the virtual network
<img width="1512" alt="image" src="https://github.com/user-attachments/assets/4178c2ea-ba5f-430a-af9a-ec19fa6132e8" />

## create and configurating virtual machine(honeypot)
Honeypot is the virtual machine with no active defense and contains the services, and file that lure the attackers to gain access, I followed below steps to create and configure a honeypot.
* configure the virtual machine on azure portal
  > go to SOC_center resource group's overview, click on create  
  > select the OS, i selected windows 10 pro 22h2 OS  
  > configure the same resource group, subscription, location, availibility zone, compute power, security type, and confirm the licence  
  > name the virtual machine as ``` credential-center-east-us-2 ```, add admin username and password, allow RDP port etc.  
  > next configure the disk for the virtual machine, and network subnet from virtual network subnets  
  > review other details, and provision the virtual machine  
<img width="1512" alt="image" src="https://github.com/user-attachments/assets/750654ae-8e9c-45a4-9a48-81be17ddc8ea" />

* configure virtual machine as honeypot
  > login to the virtual machine through RDP  
  > turn off the firewall on all public and private profile  
  > add some text file on desktop, documents, and root directories with names like credentials, secrets, client data, etc.  
  > provision some services like sql server, with bad password, and added fake data under tables  
<img width="1512" alt="image" src="https://github.com/user-attachments/assets/fc603602-ceee-4a64-907a-f178e95f3d78" />

* configure network security group on azure
  > go to SOC_center resource group > network security group > settings > inbound security rules  
  > remove rdp rule  
  > add new rule with 200 priority which allows any source ip, port to any destination ip, port, service, and name it  
  > varify the setting through pinging the machine on it's public ip  
<img width="1512" alt="image" src="https://github.com/user-attachments/assets/0444cad2-25c6-4def-8cc0-39ad08388a58" />

## configure new log analytic workspace
log analytics workspace is storage and analytical service in azure, which further used by microsoft sentinal to run different query on data.
* configure the log analytics workspace
  > go to log analytics workspace on azure portal, and create new workspace  
  > select resource group, location, and name workspace as ``` LOG-soc-center ```  
  > finally reiew and create the workspace  
## configure microsoft sentinal with the log analytic workspace
microsoft sentinal is SIEM tool, allows us to monitor the large amount of information through queries like KQL, set alerts, detect incedents etc.
* configure microsoft sentinal  
  > go to microsoft sentinal porttal  
  > click on new workspace  
  > select the log analytics workspace  

## ingest logs from honeypot to microsoft sentinal
* ingest log in log analytics workspace
  > go to the microstft sentinal > LOG-soc-center > content management > content hub > windows security events 
  > install the app 
  > go to manage the app 
  > ingest logs by creating rule with windows security events via AMA 
  > wait for a while, and varify the integration through kql query 
## extract event's with failed login, API call failed login ip to get geolocation on honeypot
to extract the event I ran following code on the powershell to see live login failure and put it in the file
```

$LOGFILE_PATH = "C:\\failed_rdp.log"

$XMLFilter = @'
<QueryList> 
   <Query Id="0" Path="Security">
         <Select Path="Security">
              *[System[(EventID='4625')]]
          </Select>
    </Query>
</QueryList> 
'@

if ((Test-Path $LOGFILE_PATH) -eq $false) {
    New-Item -ItemType File -Path $LOGFILE_PATH
}

while ($true)
{
    Start-Sleep -Seconds 1
    $events = Get-WinEvent -FilterXml $XMLFilter -ErrorAction SilentlyContinue
    foreach ($event in $events) {
        if ($event.properties[19].Value.Length -ge 5) {
            $timestamp = $event.TimeCreated
            $year = $event.TimeCreated.Year
            $month = $event.TimeCreated.Month
            if ("$($event.TimeCreated.Month)".Length -eq 1) {
                $month = "0$($event.TimeCreated.Month)"
            }
            $day = $event.TimeCreated.Day
            if ("$($event.TimeCreated.Day)".Length -eq 1) {
                $day = "0$($event.TimeCreated.Day)"
            }
            $hour = $event.TimeCreated.Hour
            if ("$($event.TimeCreated.Hour)".Length -eq 1) {
                $hour = "0$($event.TimeCreated.Hour)"
            }
            $minute = $event.TimeCreated.Minute
            if ("$($event.TimeCreated.Minute)".Length -eq 1) {
                $minute = "0$($event.TimeCreated.Minute)"
            }
            $second = $event.TimeCreated.Second
            if ("$($event.TimeCreated.Second)".Length -eq 1) {
                $second = "0$($event.TimeCreated.Second)"
            }
            $timestamp = "$($year)-$($month)-$($day) $($hour):$($minute):$($second)"
            $eventId = $event.Id
            $destinationHost = $event.MachineName# Workstation Name (Destination)
            $username = $event.properties[5].Value
            $sourceHost = $event.properties[11].Value
            $sourceIp = $event.properties[19].Value
            $log_contents = Get-Content -Path $LOGFILE_PATH
            if (-Not ($log_contents -match "$($timestamp)") -or ($log_contents.Length -eq 0)) {
            
                Start-Sleep -Seconds 1
                $API_ENDPOINT = "https://api.ipgeolocation.io/ipgeo?apiKey=f5da0ef548b7412eb2364965fbcd20e3&ip=$($sourceIp)"
                $response = Invoke-WebRequest -UseBasicParsing -Uri $API_ENDPOINT
                $responseData = $response.Content | ConvertFrom-Json
                $latitude = $responseData.latitude
                $longitude = $responseData.longitude
                $state_prov = $responseData.state_prov
                if ($state_prov -eq "") { $state_prov = "null" }
                $country = $responseData.country_name
                if ($country -eq "") {$country -eq "null"}

                "latitude:$($latitude),longitude:$($longitude),destinationhost:$($destinationHost),username:$($username),sourcehost:$($sourceIp),state:$($state_prov), country:$($country),label:$($country) - $($sourceIp),timestamp:$($timestamp)" | Out-File $LOGFILE_PATH -Append -Encoding utf8

                Write-Host -BackgroundColor Black -ForegroundColor Magenta "latitude:$($latitude),longitude:$($longitude),destinationhost:$($destinationHost),username:$($username),sourcehost:$($sourceIp),state:$($state_prov),label:$($country) - $($sourceIp),timestamp:$($timestamp)"
            }
            
        }
    }
}
```
<img width="1512" alt="image" src="https://github.com/user-attachments/assets/c381f854-62b3-44c3-ba42-43e3edb04b87" />

## create custom logs in log analytics workspace to ingest events enriched with geolocations
now to ingest this log file we just created in the log analytics workspace, we need to create custom logs,
* create custom logs
  > go to analytics workspace > settings > tables
  > create new MMA based table
  > add sample logs which will provide the insight to log analytics about the logs
  > click next, select windows, and provide log file path where previous code pushes the logs with geolocation
  > add name and description, and create the table
wait for few hours while log analytics fetches the logs from the custom log file


## extracting fields from raw data
## maping fields on dashboard to visualize data

## conclusion
