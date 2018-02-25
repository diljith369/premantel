package threatintelstructs

import "time"

type Vturlscanresult struct {
	Data []struct {
		Attributes struct {
			Categories struct {
				BitDefender            string `json:"BitDefender"`
				DrWeb                  string `json:"Dr.Web"`
				ForcepointThreatSeeker string `json:"Forcepoint ThreatSeeker"`
			} `json:"categories"`
			FirstSubmissionDate int `json:"first_submission_date"`
			LastAnalysisDate    int `json:"last_analysis_date"`
			LastAnalysisResults struct {
				ADMINUSLabs struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"ADMINUSLabs"`
				AegisLabWebGuard struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"AegisLab WebGuard"`
				AlienVault struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"AlienVault"`
				AntiyAVL struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Antiy-AVL"`
				AutoShun struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"AutoShun"`
				Avira struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Avira"`
				BaiduInternational struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Baidu-International"`
				BitDefender struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"BitDefender"`
				Blueliv struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Blueliv"`
				CSIRT struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"C-SIRT"`
				CLEANMX struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"CLEAN MX"`
				Certly struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Certly"`
				ComodoSiteInspector struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Comodo Site Inspector"`
				CyRadar struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"CyRadar"`
				CyberCrime struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"CyberCrime"`
				DNS8 struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"DNS8"`
				DrWeb struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Dr.Web"`
				ESET struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"ESET"`
				Emsisoft struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Emsisoft"`
				ForcepointThreatSeeker struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Forcepoint ThreatSeeker"`
				Fortinet struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Fortinet"`
				FraudScore struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"FraudScore"`
				FraudSense struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"FraudSense"`
				GData struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"G-Data"`
				GoogleSafebrowsing struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Google Safebrowsing"`
				K7AntiVirus struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"K7AntiVirus"`
				Kaspersky struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Kaspersky"`
				Malc0DeDatabase struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Malc0de Database"`
				Malekal struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Malekal"`
				MalwareDomainBlocklist struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Malware Domain Blocklist"`
				MalwareDomainList struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"MalwareDomainList"`
				MalwarePatrol struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"MalwarePatrol"`
				MalwarebytesHpHosts struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Malwarebytes hpHosts"`
				Malwared struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Malwared"`
				Netcraft struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Netcraft"`
				Nucleon struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Nucleon"`
				OpenPhish struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"OpenPhish"`
				Opera struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Opera"`
				PhishLabs struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"PhishLabs"`
				Phishtank struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Phishtank"`
				Quttera struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Quttera"`
				Rising struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Rising"`
				SCUMWAREOrg struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"SCUMWARE.org"`
				SecureBrain struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"SecureBrain"`
				Sophos struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Sophos"`
				Spam404 struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Spam404"`
				StopBadware struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"StopBadware"`
				SucuriSiteCheck struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Sucuri SiteCheck"`
				Tencent struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Tencent"`
				ThreatHive struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"ThreatHive"`
				Trustwave struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Trustwave"`
				URLQuery struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"URLQuery"`
				VXVault struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"VX Vault"`
				VirusdieExternalSiteScan struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Virusdie External Site Scan"`
				WebSecurityGuard struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Web Security Guard"`
				Webutation struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Webutation"`
				YandexSafebrowsing struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Yandex Safebrowsing"`
				ZCloudsec struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"ZCloudsec"`
				ZDBZeus struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"ZDB Zeus"`
				ZeroCERT struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"ZeroCERT"`
				Zerofox struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"Zerofox"`
				ZeusTracker struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"ZeusTracker"`
				DesenmascaraMe struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"desenmascara.me"`
				MalwaresComURLChecker struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"malwares.com URL checker"`
				Securolytics struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"securolytics"`
				Zvelo struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  interface{} `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        string      `json:"result"`
				} `json:"zvelo"`
			} `json:"last_analysis_results"`
			LastAnalysisStats struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Timeout    int `json:"timeout"`
				Undetected int `json:"undetected"`
			} `json:"last_analysis_stats"`
			LastFinalURL                  string `json:"last_final_url"`
			LastHTTPResponseCode          int    `json:"last_http_response_code"`
			LastHTTPResponseContentSha256 string `json:"last_http_response_content_sha256"`
			LastHTTPResponseHeaders       struct {
				CacheControl     string `json:"cache-control"`
				Connection       string `json:"connection"`
				ContentType      string `json:"content-type"`
				Date             string `json:"date"`
				Expires          string `json:"expires"`
				KeepAlive        string `json:"keep-alive"`
				LastModified     string `json:"last-modified"`
				Pragma           string `json:"pragma"`
				Server           string `json:"server"`
				SetCookie        string `json:"set-cookie"`
				TransferEncoding string `json:"transfer-encoding"`
			} `json:"last_http_response_headers"`
			LastSubmissionDate int           `json:"last_submission_date"`
			Reputation         int           `json:"reputation"`
			Tags               []interface{} `json:"tags"`
			TimesSubmitted     int           `json:"times_submitted"`
			TotalVotes         struct {
				Harmless  int `json:"harmless"`
				Malicious int `json:"malicious"`
			} `json:"total_votes"`
			URL string `json:"url"`
		} `json:"attributes"`
		ID    string `json:"id"`
		Links struct {
			Self string `json:"self"`
		} `json:"links"`
		Relationships struct {
			LastServingIPAddress struct {
				Data struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				} `json:"data"`
				Links struct {
					Related string `json:"related"`
					Self    string `json:"self"`
				} `json:"links"`
			} `json:"last_serving_ip_address"`
			NetworkLocation struct {
				Data struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				} `json:"data"`
				Links struct {
					Related string `json:"related"`
					Self    string `json:"self"`
				} `json:"links"`
			} `json:"network_location"`
		} `json:"relationships"`
		Type string `json:"type"`
	} `json:"data"`
	Links struct {
		Self string `json:"self"`
	} `json:"links"`
}

type Vtexescanresult struct {
	Data []struct {
		Attributes struct {
			Authentihash string `json:"authentihash"`
			Behaviour    struct {
				Extra      []interface{} `json:"extra"`
				Filesystem struct {
					Copied     []interface{} `json:"copied"`
					Deleted    []interface{} `json:"deleted"`
					Downloaded []interface{} `json:"downloaded"`
					Moved      []interface{} `json:"moved"`
					Opened     []struct {
						Path    string `json:"path"`
						Success bool   `json:"success"`
					} `json:"opened"`
					Read     []interface{} `json:"read"`
					Replaced []interface{} `json:"replaced"`
					Written  []interface{} `json:"written"`
				} `json:"filesystem"`
				Hooking   []interface{} `json:"hooking"`
				HostsFile interface{}   `json:"hosts_file"`
				Mutex     struct {
					Created []struct {
						Mutex   string `json:"mutex"`
						Success bool   `json:"success"`
					} `json:"created"`
					Opened []interface{} `json:"opened"`
				} `json:"mutex"`
				Network struct {
					DNS  []interface{} `json:"dns"`
					HTTP []interface{} `json:"http"`
					TCP  []interface{} `json:"tcp"`
					UDP  []string      `json:"udp"`
				} `json:"network"`
				Process struct {
					Created    []interface{} `json:"created"`
					Injected   []interface{} `json:"injected"`
					Shellcmds  []interface{} `json:"shellcmds"`
					Terminated []interface{} `json:"terminated"`
					Tree       []interface{} `json:"tree"`
				} `json:"process"`
				Registry struct {
					Deleted []interface{} `json:"deleted"`
					Set     []interface{} `json:"set"`
				} `json:"registry"`
				RuntimeDlls []struct {
					File    string `json:"file"`
					Success bool   `json:"success"`
				} `json:"runtime-dlls"`
				Service struct {
					Controlled     []interface{} `json:"controlled"`
					Created        []interface{} `json:"created"`
					Deleted        []interface{} `json:"deleted"`
					Opened         []interface{} `json:"opened"`
					OpenedManagers []interface{} `json:"opened-managers"`
					Started        []interface{} `json:"started"`
				} `json:"service"`
				Version string `json:"version"`
				Windows struct {
					Searched []interface{} `json:"searched"`
				} `json:"windows"`
			} `json:"behaviour"`
			CreationDate int `json:"creation_date"`
			Exiftool     struct {
				CharacterSet          string `json:"CharacterSet"`
				CodeSize              string `json:"CodeSize"`
				CompanyName           string `json:"CompanyName"`
				EntryPoint            string `json:"EntryPoint"`
				FileDescription       string `json:"FileDescription"`
				FileFlagsMask         string `json:"FileFlagsMask"`
				FileOS                string `json:"FileOS"`
				FileSubtype           string `json:"FileSubtype"`
				FileType              string `json:"FileType"`
				FileTypeExtension     string `json:"FileTypeExtension"`
				FileVersion           string `json:"FileVersion"`
				FileVersionNumber     string `json:"FileVersionNumber"`
				ImageVersion          string `json:"ImageVersion"`
				InitializedDataSize   string `json:"InitializedDataSize"`
				InternalName          string `json:"InternalName"`
				LanguageCode          string `json:"LanguageCode"`
				LegalCopyright        string `json:"LegalCopyright"`
				LinkerVersion         string `json:"LinkerVersion"`
				MIMEType              string `json:"MIMEType"`
				MachineType           string `json:"MachineType"`
				OSVersion             string `json:"OSVersion"`
				ObjectFileType        string `json:"ObjectFileType"`
				OriginalFileName      string `json:"OriginalFileName"`
				PEType                string `json:"PEType"`
				ProductName           string `json:"ProductName"`
				ProductVersion        string `json:"ProductVersion"`
				ProductVersionNumber  string `json:"ProductVersionNumber"`
				Subsystem             string `json:"Subsystem"`
				SubsystemVersion      string `json:"SubsystemVersion"`
				TimeStamp             string `json:"TimeStamp"`
				UninitializedDataSize string `json:"UninitializedDataSize"`
			} `json:"exiftool"`
			FirstSeenItwDate    int `json:"first_seen_itw_date"`
			FirstSubmissionDate int `json:"first_submission_date"`
			LastAnalysisDate    int `json:"last_analysis_date"`
			LastAnalysisResults struct {
				ALYac struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"ALYac"`
				AVG struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"AVG"`
				AVware struct {
					Category      string `json:"category"`
					EngineName    string `json:"engine_name"`
					EngineUpdate  string `json:"engine_update"`
					EngineVersion string `json:"engine_version"`
					Method        string `json:"method"`
					Result        string `json:"result"`
				} `json:"AVware"`
				AdAware struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"Ad-Aware"`
				AegisLab struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"AegisLab"`
				AhnLabV3 struct {
					Category      string `json:"category"`
					EngineName    string `json:"engine_name"`
					EngineUpdate  string `json:"engine_update"`
					EngineVersion string `json:"engine_version"`
					Method        string `json:"method"`
					Result        string `json:"result"`
				} `json:"AhnLab-V3"`
				Alibaba struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"Alibaba"`
				AntiyAVL struct {
					Category      string `json:"category"`
					EngineName    string `json:"engine_name"`
					EngineUpdate  string `json:"engine_update"`
					EngineVersion string `json:"engine_version"`
					Method        string `json:"method"`
					Result        string `json:"result"`
				} `json:"Antiy-AVL"`
				Arcabit struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"Arcabit"`
				Avast struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"Avast"`
				AvastMobile struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"Avast-Mobile"`
				Avira struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"Avira"`
				Baidu struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"Baidu"`
				BitDefender struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"BitDefender"`
				Bkav struct {
					Category      string `json:"category"`
					EngineName    string `json:"engine_name"`
					EngineUpdate  string `json:"engine_update"`
					EngineVersion string `json:"engine_version"`
					Method        string `json:"method"`
					Result        string `json:"result"`
				} `json:"Bkav"`
				CATQuickHeal struct {
					Category      string `json:"category"`
					EngineName    string `json:"engine_name"`
					EngineUpdate  string `json:"engine_update"`
					EngineVersion string `json:"engine_version"`
					Method        string `json:"method"`
					Result        string `json:"result"`
				} `json:"CAT-QuickHeal"`
				CMC struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"CMC"`
				ClamAV struct {
					Category      string `json:"category"`
					EngineName    string `json:"engine_name"`
					EngineUpdate  string `json:"engine_update"`
					EngineVersion string `json:"engine_version"`
					Method        string `json:"method"`
					Result        string `json:"result"`
				} `json:"ClamAV"`
				Comodo struct {
					Category      string `json:"category"`
					EngineName    string `json:"engine_name"`
					EngineUpdate  string `json:"engine_update"`
					EngineVersion string `json:"engine_version"`
					Method        string `json:"method"`
					Result        string `json:"result"`
				} `json:"Comodo"`
				CrowdStrike struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"CrowdStrike"`
				Cybereason struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"Cybereason"`
				Cylance struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"Cylance"`
				Cyren struct {
					Category      string `json:"category"`
					EngineName    string `json:"engine_name"`
					EngineUpdate  string `json:"engine_update"`
					EngineVersion string `json:"engine_version"`
					Method        string `json:"method"`
					Result        string `json:"result"`
				} `json:"Cyren"`
				DrWeb struct {
					Category      string `json:"category"`
					EngineName    string `json:"engine_name"`
					EngineUpdate  string `json:"engine_update"`
					EngineVersion string `json:"engine_version"`
					Method        string `json:"method"`
					Result        string `json:"result"`
				} `json:"DrWeb"`
				ESETNOD32 struct {
					Category      string `json:"category"`
					EngineName    string `json:"engine_name"`
					EngineUpdate  string `json:"engine_update"`
					EngineVersion string `json:"engine_version"`
					Method        string `json:"method"`
					Result        string `json:"result"`
				} `json:"ESET-NOD32"`
				Emsisoft struct {
					Category      string `json:"category"`
					EngineName    string `json:"engine_name"`
					EngineUpdate  string `json:"engine_update"`
					EngineVersion string `json:"engine_version"`
					Method        string `json:"method"`
					Result        string `json:"result"`
				} `json:"Emsisoft"`
				Endgame struct {
					Category      string `json:"category"`
					EngineName    string `json:"engine_name"`
					EngineUpdate  string `json:"engine_update"`
					EngineVersion string `json:"engine_version"`
					Method        string `json:"method"`
					Result        string `json:"result"`
				} `json:"Endgame"`
				FProt struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"F-Prot"`
				FSecure struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"F-Secure"`
				Fortinet struct {
					Category      string `json:"category"`
					EngineName    string `json:"engine_name"`
					EngineUpdate  string `json:"engine_update"`
					EngineVersion string `json:"engine_version"`
					Method        string `json:"method"`
					Result        string `json:"result"`
				} `json:"Fortinet"`
				GData struct {
					Category      string `json:"category"`
					EngineName    string `json:"engine_name"`
					EngineUpdate  string `json:"engine_update"`
					EngineVersion string `json:"engine_version"`
					Method        string `json:"method"`
					Result        string `json:"result"`
				} `json:"GData"`
				Ikarus struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"Ikarus"`
				Invincea struct {
					Category      string `json:"category"`
					EngineName    string `json:"engine_name"`
					EngineUpdate  string `json:"engine_update"`
					EngineVersion string `json:"engine_version"`
					Method        string `json:"method"`
					Result        string `json:"result"`
				} `json:"Invincea"`
				Jiangmin struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"Jiangmin"`
				K7AntiVirus struct {
					Category      string `json:"category"`
					EngineName    string `json:"engine_name"`
					EngineUpdate  string `json:"engine_update"`
					EngineVersion string `json:"engine_version"`
					Method        string `json:"method"`
					Result        string `json:"result"`
				} `json:"K7AntiVirus"`
				K7GW struct {
					Category      string `json:"category"`
					EngineName    string `json:"engine_name"`
					EngineUpdate  string `json:"engine_update"`
					EngineVersion string `json:"engine_version"`
					Method        string `json:"method"`
					Result        string `json:"result"`
				} `json:"K7GW"`
				Kaspersky struct {
					Category      string `json:"category"`
					EngineName    string `json:"engine_name"`
					EngineUpdate  string `json:"engine_update"`
					EngineVersion string `json:"engine_version"`
					Method        string `json:"method"`
					Result        string `json:"result"`
				} `json:"Kaspersky"`
				Kingsoft struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"Kingsoft"`
				MAX struct {
					Category      string `json:"category"`
					EngineName    string `json:"engine_name"`
					EngineUpdate  string `json:"engine_update"`
					EngineVersion string `json:"engine_version"`
					Method        string `json:"method"`
					Result        string `json:"result"`
				} `json:"MAX"`
				Malwarebytes struct {
					Category      string `json:"category"`
					EngineName    string `json:"engine_name"`
					EngineUpdate  string `json:"engine_update"`
					EngineVersion string `json:"engine_version"`
					Method        string `json:"method"`
					Result        string `json:"result"`
				} `json:"Malwarebytes"`
				McAfee struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"McAfee"`
				McAfeeGWEdition struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"McAfee-GW-Edition"`
				MicroWorldEScan struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"MicroWorld-eScan"`
				Microsoft struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"Microsoft"`
				NANOAntivirus struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"NANO-Antivirus"`
				Paloalto struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"Paloalto"`
				Panda struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"Panda"`
				Qihoo360 struct {
					Category      string `json:"category"`
					EngineName    string `json:"engine_name"`
					EngineUpdate  string `json:"engine_update"`
					EngineVersion string `json:"engine_version"`
					Method        string `json:"method"`
					Result        string `json:"result"`
				} `json:"Qihoo-360"`
				Rising struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"Rising"`
				SUPERAntiSpyware struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"SUPERAntiSpyware"`
				SentinelOne struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"SentinelOne"`
				Sophos struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"Sophos"`
				Symantec struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"Symantec"`
				SymantecMobileInsight struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"SymantecMobileInsight"`
				Tencent struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"Tencent"`
				TheHacker struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"TheHacker"`
				TotalDefense struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"TotalDefense"`
				TrendMicro struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"TrendMicro"`
				TrendMicroHouseCall struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"TrendMicro-HouseCall"`
				Trustlook struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"Trustlook"`
				VBA32 struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"VBA32"`
				VIPRE struct {
					Category      string `json:"category"`
					EngineName    string `json:"engine_name"`
					EngineUpdate  string `json:"engine_update"`
					EngineVersion string `json:"engine_version"`
					Method        string `json:"method"`
					Result        string `json:"result"`
				} `json:"VIPRE"`
				ViRobot struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"ViRobot"`
				Webroot struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"Webroot"`
				WhiteArmor struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion interface{} `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"WhiteArmor"`
				Yandex struct {
					Category      string `json:"category"`
					EngineName    string `json:"engine_name"`
					EngineUpdate  string `json:"engine_update"`
					EngineVersion string `json:"engine_version"`
					Method        string `json:"method"`
					Result        string `json:"result"`
				} `json:"Yandex"`
				Zillya struct {
					Category      string `json:"category"`
					EngineName    string `json:"engine_name"`
					EngineUpdate  string `json:"engine_update"`
					EngineVersion string `json:"engine_version"`
					Method        string `json:"method"`
					Result        string `json:"result"`
				} `json:"Zillya"`
				ZoneAlarm struct {
					Category      string `json:"category"`
					EngineName    string `json:"engine_name"`
					EngineUpdate  string `json:"engine_update"`
					EngineVersion string `json:"engine_version"`
					Method        string `json:"method"`
					Result        string `json:"result"`
				} `json:"ZoneAlarm"`
				Zoner struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"Zoner"`
				EGambit struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"eGambit"`
				NProtect struct {
					Category      string      `json:"category"`
					EngineName    string      `json:"engine_name"`
					EngineUpdate  string      `json:"engine_update"`
					EngineVersion string      `json:"engine_version"`
					Method        string      `json:"method"`
					Result        interface{} `json:"result"`
				} `json:"nProtect"`
			} `json:"last_analysis_results"`
			LastAnalysisStats struct {
				Failure         int `json:"failure"`
				Harmless        int `json:"harmless"`
				Malicious       int `json:"malicious"`
				Suspicious      int `json:"suspicious"`
				Timeout         int `json:"timeout"`
				TypeUnsupported int `json:"type-unsupported"`
				Undetected      int `json:"undetected"`
			} `json:"last_analysis_stats"`
			LastSubmissionDate int      `json:"last_submission_date"`
			Magic              string   `json:"magic"`
			Md5                string   `json:"md5"`
			Names              []string `json:"names"`
			PeInfo             struct {
				Debug []struct {
					Codeview struct {
						Age       int    `json:"age"`
						GUID      string `json:"guid"`
						Name      string `json:"name"`
						Signature string `json:"signature"`
					} `json:"codeview,omitempty"`
					Offset        int    `json:"offset"`
					Size          int    `json:"size"`
					Timedatestamp string `json:"timedatestamp"`
					Type          int    `json:"type"`
					TypeStr       string `json:"type_str"`
				} `json:"debug"`
				EntryPoint int    `json:"entry_point"`
				Imphash    string `json:"imphash"`
				Imports    struct {
					ADVAPI32Dll []string `json:"ADVAPI32.dll"`
					COMCTL32Dll []string `json:"COMCTL32.dll"`
					CRYPT32Dll  []string `json:"CRYPT32.dll"`
					GDI32Dll    []string `json:"GDI32.dll"`
					KERNEL32Dll []string `json:"KERNEL32.dll"`
					MSIMG32Dll  []string `json:"MSIMG32.dll"`
					OLEACCDll   []string `json:"OLEACC.dll"`
					OLEAUT32Dll []string `json:"OLEAUT32.dll"`
					PSAPIDLL    []string `json:"PSAPI.DLL"`
					SHELL32Dll  []string `json:"SHELL32.dll"`
					SHLWAPIDll  []string `json:"SHLWAPI.dll"`
					USER32Dll   []string `json:"USER32.dll"`
					VERSIONDll  []string `json:"VERSION.dll"`
					WININETDll  []string `json:"WININET.dll"`
					WINTRUSTDll []string `json:"WINTRUST.dll"`
					WS232Dll    []string `json:"WS2_32.dll"`
					WTSAPI32Dll []string `json:"WTSAPI32.dll"`
					GdiplusDll  []string `json:"gdiplus.dll"`
					MsiDll      []string `json:"msi.dll"`
					Ole32Dll    []string `json:"ole32.dll"`
				} `json:"imports"`
				MachineType int `json:"machine_type"`
				Overlay     struct {
					Entropy  float64 `json:"entropy"`
					Filetype string  `json:"filetype"`
					Md5      string  `json:"md5"`
					Offset   int     `json:"offset"`
					Size     int     `json:"size"`
				} `json:"overlay"`
				ResourceDetails []struct {
					Filetype string `json:"filetype"`
					Lang     string `json:"lang"`
					Sha256   string `json:"sha256"`
					Type     string `json:"type"`
				} `json:"resource_details"`
				ResourceLangs struct {
					ENGLISHUS int `json:"ENGLISH US"`
				} `json:"resource_langs"`
				ResourceTypes struct {
					PNG         int `json:"PNG"`
					REGISTRY    int `json:"REGISTRY"`
					RTDIALOG    int `json:"RT_DIALOG"`
					RTGROUPICON int `json:"RT_GROUP_ICON"`
					RTICON      int `json:"RT_ICON"`
					RTMANIFEST  int `json:"RT_MANIFEST"`
					RTSTRING    int `json:"RT_STRING"`
					RTVERSION   int `json:"RT_VERSION"`
					TYPELIB     int `json:"TYPELIB"`
				} `json:"resource_types"`
				Sections []struct {
					Entropy        float64 `json:"entropy"`
					Md5            string  `json:"md5"`
					Name           string  `json:"name"`
					RawSize        int     `json:"raw_size"`
					VirtualAddress int     `json:"virtual_address"`
					VirtualSize    int     `json:"virtual_size"`
				} `json:"sections"`
				Timestamp int `json:"timestamp"`
			} `json:"pe_info"`
			Reputation    int    `json:"reputation"`
			Sha1          string `json:"sha1"`
			Sha256        string `json:"sha256"`
			SignatureInfo struct {
				Copyright             string `json:"copyright"`
				CounterSigners        string `json:"counter signers"`
				CounterSignersDetails []struct {
					Algorithm    string `json:"algorithm"`
					CertIssuer   string `json:"cert issuer"`
					Name         string `json:"name"`
					SerialNumber string `json:"serial number"`
					Status       string `json:"status"`
					Thumbprint   string `json:"thumbprint"`
					ValidFrom    string `json:"valid from"`
					ValidTo      string `json:"valid to"`
					ValidUsage   string `json:"valid usage"`
				} `json:"counter signers details"`
				Description    string `json:"description"`
				FileVersion    string `json:"file version"`
				InternalName   string `json:"internal name"`
				OriginalName   string `json:"original name"`
				Product        string `json:"product"`
				Signers        string `json:"signers"`
				SignersDetails []struct {
					Algorithm    string `json:"algorithm"`
					CertIssuer   string `json:"cert issuer"`
					Name         string `json:"name"`
					SerialNumber string `json:"serial number"`
					Status       string `json:"status"`
					Thumbprint   string `json:"thumbprint"`
					ValidFrom    string `json:"valid from"`
					ValidTo      string `json:"valid to"`
					ValidUsage   string `json:"valid usage"`
				} `json:"signers details"`
				SigningDate string `json:"signing date"`
				Verified    string `json:"verified"`
			} `json:"signature_info"`
			Size           int      `json:"size"`
			Ssdeep         string   `json:"ssdeep"`
			Tags           []string `json:"tags"`
			TimesSubmitted int      `json:"times_submitted"`
			TotalVotes     struct {
				Harmless  int `json:"harmless"`
				Malicious int `json:"malicious"`
			} `json:"total_votes"`
			Trid []struct {
				FileType    string  `json:"file_type"`
				Probability float64 `json:"probability"`
			} `json:"trid"`
			TypeDescription string   `json:"type_description"`
			TypeTag         string   `json:"type_tag"`
			Vhash           string   `json:"vhash"`
			ZemanaBehaviour []string `json:"zemana_behaviour"`
		} `json:"attributes"`
		ID    string `json:"id"`
		Links struct {
			Self string `json:"self"`
		} `json:"links"`
		Type string `json:"type"`
	} `json:"data"`
	Links struct {
		Self string `json:"self"`
	} `json:"links"`
}

type JottiVirusScanToken struct {
	ScanToken string `json:"scanToken"`
}

type JottiVirusScanFileScanJobID struct {
	FileScanJobID string `json:"fileScanJobId"`
}

type JottiVirusScanResult struct {
	File struct {
		Name      string `json:"name"`
		Size      int    `json:"size"`
		Type      string `json:"type"`
		FirstSeen string `json:"firstSeen"`
		Hashes    struct {
			Md5    string `json:"md5"`
			Sha1   string `json:"sha1"`
			Sha256 string `json:"sha256"`
			Sha512 string `json:"sha512"`
		} `json:"hashes"`
	} `json:"file"`
	ScanJob struct {
		ID               string      `json:"id"`
		WebURL           string      `json:"webUrl"`
		PlaceInQueue     interface{} `json:"placeInQueue"`
		StartedOn        string      `json:"startedOn"`
		FinishedOn       interface{} `json:"finishedOn"`
		ScannersRun      int         `json:"scannersRun"`
		ScannersDetected int         `json:"scannersDetected"`
		ScannerResults   []struct {
			ScannerID                   string      `json:"scannerId"`
			ScannerName                 string      `json:"scannerName"`
			ScannerLogoURL              string      `json:"scannerLogoUrl"`
			Finished                    bool        `json:"finished"`
			FinishedWithoutResultReason interface{} `json:"finishedWithoutResultReason"`
			MalwareName                 string      `json:"malwareName"`
			SignatureFileDate           string      `json:"signatureFileDate"`
		} `json:"scannerResults"`
		MetaData []interface{} `json:"metaData"`
	} `json:"scanJob"`
}

type MetaDefenderDataID struct {
	DataID  string `json:"data_id"`
	Status  string `json:"status"`
	InQueue int    `json:"in_queue"`
	RestIP  string `json:"rest_ip"`
}

type MetaDefenderScanResult struct {
	FileID    string `json:"file_id"`
	DataID    string `json:"data_id"`
	Sanitized struct {
		FilePath string `json:"file_path"`
		DataID   string `json:"data_id"`
		Result   string `json:"result"`
	} `json:"sanitized"`
	ScanResults struct {
		ScanDetails struct {
			Ahnlab struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"Ahnlab"`
			Antiy struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"Antiy"`
			Avira struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"Avira"`
			Fortinet struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"Fortinet"`
			FProt struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"F-prot"`
			Ikarus struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"Ikarus"`
			K7 struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"K7"`
			McAfee struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"McAfee"`
			NProtect struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"nProtect"`
			Preventon struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"Preventon"`
			QuickHeal struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"QuickHeal"`
			Sophos struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"Sophos"`
			TotalDefense struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"TotalDefense"`
			Zillya struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"Zillya!"`
			Zoner struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"Zoner"`
			AegisLab struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"AegisLab"`
			Agnitum struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"Agnitum"`
			AVG struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"AVG"`
			Baidu struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"Baidu"`
			BitDefender struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"BitDefender"`
			ByteHero struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"ByteHero"`
			ClamAV struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"ClamAV"`
			CYREN struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"CYREN"`
			DrWebGateway struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"DrWebGateway"`
			Emsisoft struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"Emsisoft"`
			ESET struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"ESET"`
			Filseclab struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"Filseclab"`
			FSecure struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"F-secure"`
			Hauri struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"Hauri"`
			Jiangmin struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"Jiangmin"`
			Microsoft struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"Microsoft"`
			NANOAV struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"NANOAV"`
			SUPERAntiSpyware struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"SUPERAntiSpyware"`
			Symantec struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"Symantec"`
			ThreatTrack struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"ThreatTrack"`
			TrendMicro struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"TrendMicro"`
			TrendMicroHouseCall struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"TrendMicroHouseCall"`
			VirITeXplorer struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"VirITeXplorer"`
			VirusBlokAda struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"VirusBlokAda"`
			Xvirus struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"Xvirus"`
			Lavasoft struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"Lavasoft"`
			STOPzilla struct {
				ThreatFound string    `json:"threat_found"`
				ScanResultI int       `json:"scan_result_i"`
				DefTime     time.Time `json:"def_time"`
				ScanTime    int       `json:"scan_time"`
			} `json:"STOPzilla"`
		} `json:"scan_details"`
		RescanAvailable    bool      `json:"rescan_available"`
		DataID             string    `json:"data_id"`
		ScanAllResultI     int       `json:"scan_all_result_i"`
		StartTime          time.Time `json:"start_time"`
		TotalTime          int       `json:"total_time"`
		TotalAvs           int       `json:"total_avs"`
		TotalDetectedAvs   int       `json:"total_detected_avs"`
		ProgressPercentage int       `json:"progress_percentage"`
		InQueue            int       `json:"in_queue"`
		ScanAllResultA     string    `json:"scan_all_result_a"`
	} `json:"scan_results"`
	FileInfo struct {
		FileSize            int       `json:"file_size"`
		UploadTimestamp     time.Time `json:"upload_timestamp"`
		Md5                 string    `json:"md5"`
		Sha1                string    `json:"sha1"`
		Sha256              string    `json:"sha256"`
		FileTypeCategory    string    `json:"file_type_category"`
		FileTypeDescription string    `json:"file_type_description"`
		FileTypeExtension   string    `json:"file_type_extension"`
		DisplayName         string    `json:"display_name"`
	} `json:"file_info"`
	TopThreat int `json:"top_threat"`
}

type CymonAuthHead struct {
	Jwt     string `json:"jwt"`
	Message string `json:"message"`
}

type CymonIPResult struct {
	Total int `json:"total"`
	From  int `json:"from"`
	Size  int `json:"size"`
	Hits  []struct {
		Title       string    `json:"title"`
		Description string    `json:"description"`
		Link        string    `json:"link"`
		ReportedBy  string    `json:"reported_by"`
		Feed        string    `json:"feed"`
		FeedID      string    `json:"feed_id"`
		Timestamp   time.Time `json:"timestamp"`
		Tags        []string  `json:"tags"`
		Ioc         struct {
			URL      string `json:"url"`
			Hostname string `json:"hostname"`
			Domain   string `json:"domain"`
			IP       string `json:"ip"`
		} `json:"ioc"`
		Location struct {
			Country string `json:"country"`
			City    string `json:"city"`
			Point   struct {
				Lon float64 `json:"lon"`
				Lat float64 `json:"lat"`
			} `json:"point"`
		} `json:"location"`
		ID      string `json:"id"`
		Ipwhois struct {
			Net struct {
				Name   interface{} `json:"name"`
				Handle string      `json:"handle"`
			} `json:"net"`
			Org struct {
				Name   string `json:"name"`
				Handle string `json:"handle"`
			} `json:"org"`
		} `json:"ipwhois,omitempty"`
	} `json:"hits"`
}

type GoogleSafeBrowsing struct {
	Matches []struct {
		ThreatType   string `json:"threatType"`
		PlatformType string `json:"platformType"`
		Threat       struct {
			URL string `json:"url"`
		} `json:"threat"`
		CacheDuration   string `json:"cacheDuration"`
		ThreatEntryType string `json:"threatEntryType"`
	} `json:"matches"`
}

type IBMxFroceIPReport struct {
	IP      string `json:"ip"`
	History []struct {
		Created time.Time `json:"created"`
		Reason  string    `json:"reason"`
		Geo     struct {
			Country     string `json:"country"`
			Countrycode string `json:"countrycode"`
		} `json:"geo"`
		IP                   string            `json:"ip"`
		CategoryDescriptions map[string]string `json:"categoryDescriptions"`
		ReasonDescription    string            `json:"reasonDescription"`
		Score                float32           `json:"score"`
		Cats                 map[string]int    `json:"cats"`
		Asns                 struct {
			Num5048 struct {
				Company string `json:"Company"`
				Cidr    int    `json:"cidr"`
			} `json:"5048"`
		} `json:"asns,omitempty"`
		MalwareExtended struct {
			CnC        string `json:"CnC"`
			CncCountry int    `json:"cnc_country"`
			CncIsnew   bool   `json:"cnc_isnew"`
		} `json:"malware_extended,omitempty"`
		Deleted bool `json:"deleted,omitempty"`
	} `json:"history"`
	Subnets []struct {
		Created time.Time `json:"created"`
		Reason  string    `json:"reason"`
		Asns    struct {
			Num5048 struct {
				Company string `json:"Company"`
				Cidr    int    `json:"cidr"`
			} `json:"5048"`
		} `json:"asns"`
		Geo struct {
			Country     string `json:"country"`
			Countrycode string `json:"countrycode"`
		} `json:"geo"`
		IP                   string            `json:"ip"`
		CategoryDescriptions map[string]string `json:"categoryDescriptions"`
		ReasonDescription    string            `json:"reasonDescription"`
		Score                float32           `json:"score"`
		Cats                 map[string]int    `json:"cats"`
		Subnet               string            `json:"subnet"`
	} `json:"subnets"`
	Cats map[string]int `json:"cats"`
	Geo  struct {
		Country     string `json:"country"`
		Countrycode string `json:"countrycode"`
	} `json:"geo"`
	Score                float32           `json:"score"`
	Reason               string            `json:"reason"`
	ReasonDescription    string            `json:"reasonDescription"`
	CategoryDescriptions map[string]string `json:"categoryDescriptions"`
	Tags                 []interface{}     `json:"tags"`
}

type IBMxForceIPMalwareReport struct {
	Malware []struct {
		Type      string    `json:"type"`
		Md5       string    `json:"md5"`
		Domain    string    `json:"domain"`
		Firstseen time.Time `json:"firstseen"`
		Lastseen  time.Time `json:"lastseen"`
		IP        string    `json:"ip"`
		Count     int       `json:"count"`
		Filepath  string    `json:"filepath"`
		URI       string    `json:"uri"`
		First     time.Time `json:"first"`
		Last      time.Time `json:"last"`
		Origin    string    `json:"origin"`
		Family    []string  `json:"family"`
	} `json:"malware"`
}

type IBMxForceMalware struct {
	Malware struct {
		Origins struct {
			External struct {
				DetectionCoverage int      `json:"detectionCoverage"`
				Family            []string `json:"family"`
			} `json:"external"`
		} `json:"origins"`
		Type string `json:"type"`
		Md5  string `json:"md5"`
		Hash string `json:"hash"`
		Risk string `json:"risk"`
	} `json:"malware"`
	Tags []interface{} `json:"tags"`
}

type APIs struct {
	AppPort       string
	Safebrowse    string
	CymonUser     string
	CymonPassword string
	Jotti         string
	Metadefender  string
	IBMxForceKey  string
	IBMxForcePass string
}

type IPFeeds struct {
	MalwareDomainlistIP  string `json:"MalwareDomainlistIP"`
	SnortIPFilter        string `json:"SnortIPFilter"`
	SuricataCompromised  string `json:"SuricataCompromised"`
	AlienvaultReputation string `json:"AlienvaultReputation"`
	SuricataBotCC        string `json:"SuricataBotCC"`
	SurricataTor         string `json:"SurricataTor"`
	CiarmyBadIps         string `json:"CiarmyBadIps"`
}
type DomainFeeds struct {
	MalwareDomainHosts string `json:"MalwareDomainHosts"`
	MandiantAPT        string `json:"MandiantAPT"`
}
