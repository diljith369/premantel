# Premantel - Malware Analysis and Threat Intel Framework

##### Premantel - A threat intel and premalware analysis framework  . User can check malware files against three different malware provider's engines . Included functionality to check IOC details of hashes , urls , IPs and domains from different resources.

### Resources available for Win Exe analysis.
#### •	AvCaesar 
#### •	Virus Scan Jotti 
#### •	Metadefender

### Resources availabe for Hash analysis.
#### •	Virus Total 
#### •	ShadowServer 
#### •	IBMxForceXchange

### Resources availabe for URL analysis.
#### •	Virus Total
#### •	Google SafeBrowse
#### •	UrlQuery.net

### Resources availabe for IP analysis
#### •	IBMxForce Xchange
#### •	SnortIPFilter
#### •	SuricataCompromised
#### •	AlienvaultReputation
#### •	SuricataBotCC
#### •	SurricataTor
#### •	CiarmyBadIps

### Resource availabe for Domain analysis
#### •	Cymon.IO
#### •	MalwareDomainHosts
#### •	MandiantAPT

## Getting Started

##### git clone https://github.com/diljithishere/premantel.git
##### cd premantel/src
#### Open apiconfig.cfg under src\config folder and update with api keys from following vendors
#### GoogleSafeBrowse
#### VirusScan.Jotti
#### MetaDefender
#### Cymon.IO
#### IBMxForceXchange
#### Update AppPort if necessary (Optional)

##### go get github.com/PuerkitoBio/goquery
##### go build premantel.go (This command will generate premantel.exe)

#### Run exe 
##### > premantel.exe

##### Use your browser to access : http://localhost:8085

### Prerequisites

#### Go 1.9

## Built With
Go Lang

## Author

* **Diljith S** - *Initial work* - (https://github.com/diljithishere)
