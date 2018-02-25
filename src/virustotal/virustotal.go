package virustotal

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"../threatintelstructs"
)

var vturlres threatintelstructs.Vturlscanresult
var vtexeres threatintelstructs.Vtexescanresult
var vtscanresForDisplay map[string]string

func init() {
	vtscanresForDisplay = make(map[string]string)
}

//VtURLScanner scans urls
func VtURLScanner(searchvalue string, Vtscanres map[string]string, finflag chan string) {

	req, _ := http.NewRequest("GET", "https://www.virustotal.com/ui/search", nil)
	qstring := req.URL.Query()
	qstring.Add("query", searchvalue)
	qstring.Add("relationships[url]", "network_location,last_serving_ip_address")
	qstring.Add("relationships[comment]=", "author,item")
	req.URL.RawQuery = qstring.Encode()
	client := &http.Client{}
	resp, err := client.Do(req)

	//resp, err := http.Get("https://www.virustotal.com/ui/search?query=cc5c1ceeabf310b66e750f3e7fa4e091&relationships[url]=network_location%2Clast_serving_ip_address&relationships[comment]=author%2Citem")
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	resultbyte, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	vturlres = threatintelstructs.Vturlscanresult{}
	vtscanresForDisplay = Vtscanres
	err = json.Unmarshal(resultbyte, &vturlres)
	if err != nil {
		fmt.Println(err)
		//fmt.Println("")
	}
	if len(vturlres.Data) > 0 {
		buildVTURLresult()
	}
	finflag <- "urlscan finished"
}

func buildVTURLresult() {
	checkandaddtoresult("AlienVault", vturlres.Data[0].Attributes.LastAnalysisResults.AlienVault.Category, vturlres.Data[0].Attributes.LastAnalysisResults.AlienVault.Result)
	checkandaddtoresult("Avira", vturlres.Data[0].Attributes.LastAnalysisResults.Avira.Category, vturlres.Data[0].Attributes.LastAnalysisResults.Avira.Result)
	checkandaddtoresult("BitDefender", vturlres.Data[0].Attributes.LastAnalysisResults.BitDefender.Category, vturlres.Data[0].Attributes.LastAnalysisResults.BitDefender.Result)
	checkandaddtoresult("ComodoSiteInsp", vturlres.Data[0].Attributes.LastAnalysisResults.ComodoSiteInspector.Category, vturlres.Data[0].Attributes.LastAnalysisResults.ComodoSiteInspector.Result)
	checkandaddtoresult("DrWeb", vturlres.Data[0].Attributes.LastAnalysisResults.DrWeb.Category, vturlres.Data[0].Attributes.LastAnalysisResults.DrWeb.Result)
	checkandaddtoresult("DNS8", vturlres.Data[0].Attributes.LastAnalysisResults.DNS8.Category, vturlres.Data[0].Attributes.LastAnalysisResults.DNS8.Result)
	checkandaddtoresult("ESET", vturlres.Data[0].Attributes.LastAnalysisResults.ESET.Category, vturlres.Data[0].Attributes.LastAnalysisResults.ESET.Result)
	checkandaddtoresult("Fortinet", vturlres.Data[0].Attributes.LastAnalysisResults.Fortinet.Category, vturlres.Data[0].Attributes.LastAnalysisResults.Fortinet.Result)
	checkandaddtoresult("GoogleSafeBrows", vturlres.Data[0].Attributes.LastAnalysisResults.GoogleSafebrowsing.Category, vturlres.Data[0].Attributes.LastAnalysisResults.GoogleSafebrowsing.Result)
	checkandaddtoresult("Kaspersky", vturlres.Data[0].Attributes.LastAnalysisResults.Kaspersky.Category, vturlres.Data[0].Attributes.LastAnalysisResults.Kaspersky.Result)
	checkandaddtoresult("MalwareBytesHP", vturlres.Data[0].Attributes.LastAnalysisResults.MalwarebytesHpHosts.Category, vturlres.Data[0].Attributes.LastAnalysisResults.MalwarebytesHpHosts.Result)
	checkandaddtoresult("MalwareDomBlck", vturlres.Data[0].Attributes.LastAnalysisResults.MalwareDomainBlocklist.Category, vturlres.Data[0].Attributes.LastAnalysisResults.MalwareDomainBlocklist.Result)
	checkandaddtoresult("MalwareDomain", vturlres.Data[0].Attributes.LastAnalysisResults.MalwareDomainList.Category, vturlres.Data[0].Attributes.LastAnalysisResults.MalwareDomainList.Result)
	checkandaddtoresult("NetCraft", vturlres.Data[0].Attributes.LastAnalysisResults.Netcraft.Category, vturlres.Data[0].Attributes.LastAnalysisResults.Netcraft.Result)
	checkandaddtoresult("OpenPhish", vturlres.Data[0].Attributes.LastAnalysisResults.OpenPhish.Category, vturlres.Data[0].Attributes.LastAnalysisResults.OpenPhish.Result)
	checkandaddtoresult("PhishTank", vturlres.Data[0].Attributes.LastAnalysisResults.Phishtank.Category, vturlres.Data[0].Attributes.LastAnalysisResults.Phishtank.Result)
	checkandaddtoresult("PhishLabs", vturlres.Data[0].Attributes.LastAnalysisResults.PhishLabs.Category, vturlres.Data[0].Attributes.LastAnalysisResults.PhishLabs.Result)
	checkandaddtoresult("SophosAV", vturlres.Data[0].Attributes.LastAnalysisResults.Sophos.Category, vturlres.Data[0].Attributes.LastAnalysisResults.Sophos.Result)
	checkandaddtoresult("Spam404", vturlres.Data[0].Attributes.LastAnalysisResults.Spam404.Category, vturlres.Data[0].Attributes.LastAnalysisResults.Spam404.Result)
	checkandaddtoresult("ZeusTracker", vturlres.Data[0].Attributes.LastAnalysisResults.ZeusTracker.Category, vturlres.Data[0].Attributes.LastAnalysisResults.ZeusTracker.Result)
}

func checkandaddtoresult(avname string, category string, result interface{}) {
	switch category {
	case "malicious", "phishing":
		vtscanresForDisplay[avname] = fmt.Sprintf("%v", result)
	}
}

//VtExeScanner scans urls
func VtExeScanner(searchvalue string, Vtscanres map[string]string, VtUploadedFileInfo map[string]string, finflag chan string) {

	req, _ := http.NewRequest("GET", "https://www.virustotal.com/ui/search", nil)
	qstring := req.URL.Query()
	qstring.Add("query", searchvalue)
	qstring.Add("relationships[url]", "network_location,last_serving_ip_address")
	qstring.Add("relationships[comment]=", "author,item")
	req.URL.RawQuery = qstring.Encode()
	client := &http.Client{}
	resp, err := client.Do(req)

	//resp, err := http.Get("https://www.virustotal.com/ui/search?query=cc5c1ceeabf310b66e750f3e7fa4e091&relationships[url]=network_location%2Clast_serving_ip_address&relationships[comment]=author%2Citem")
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	resultbyte, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	vtexeres = threatintelstructs.Vtexescanresult{}
	err = json.Unmarshal(resultbyte, &vtexeres)
	if err != nil {
		fmt.Println("")
	}
	if len(vtexeres.Data) > 0 {
		vtscanresForDisplay = Vtscanres
		buildVTEXEresult()
		updatevtfileinfomap(VtUploadedFileInfo)
	}
	finflag <- "urlscan finished"
}

func updatevtfileinfomap(VtUploadedFileInfo map[string]string) {
	VtUploadedFileInfo["PEType"] = vtexeres.Data[0].Attributes.Exiftool.PEType
	VtUploadedFileInfo["FileType"] = vtexeres.Data[0].Attributes.Exiftool.FileType
	VtUploadedFileInfo["EntryPoint"] = vtexeres.Data[0].Attributes.Exiftool.EntryPoint
	VtUploadedFileInfo["FileVersion"] = vtexeres.Data[0].Attributes.Exiftool.FileVersion
	VtUploadedFileInfo["OriginalFileName"] = vtexeres.Data[0].Attributes.Exiftool.OriginalFileName
	VtUploadedFileInfo["Sha256"] = vtexeres.Data[0].Attributes.Sha256
	VtUploadedFileInfo["Md5"] = vtexeres.Data[0].Attributes.Md5
}

func buildVTEXEresult() {

	checkandaddtoresult("Avira", vtexeres.Data[0].Attributes.LastAnalysisResults.Avira.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.Avira.Result)
	checkandaddtoresult("Avast", vtexeres.Data[0].Attributes.LastAnalysisResults.Avast.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.Avast.Result)
	checkandaddtoresult("AVG", vtexeres.Data[0].Attributes.LastAnalysisResults.AVG.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.AVG.Result)
	checkandaddtoresult("BitDefender", vtexeres.Data[0].Attributes.LastAnalysisResults.BitDefender.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.BitDefender.Result)
	checkandaddtoresult("CrowdStrike", vtexeres.Data[0].Attributes.LastAnalysisResults.CrowdStrike.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.CrowdStrike.Result)
	checkandaddtoresult("Cylance", vtexeres.Data[0].Attributes.LastAnalysisResults.Cylance.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.Cylance.Result)
	checkandaddtoresult("CyberReason", vtexeres.Data[0].Attributes.LastAnalysisResults.Cybereason.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.Cybereason.Result)
	checkandaddtoresult("EndGame", vtexeres.Data[0].Attributes.LastAnalysisResults.Endgame.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.Endgame.Result)
	checkandaddtoresult("ESETNode", vtexeres.Data[0].Attributes.LastAnalysisResults.ESETNOD32.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.ESETNOD32.Result)
	checkandaddtoresult("Fortinet", vtexeres.Data[0].Attributes.LastAnalysisResults.Fortinet.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.Fortinet.Result)
	checkandaddtoresult("Kaspersky", vtexeres.Data[0].Attributes.LastAnalysisResults.Kaspersky.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.Kaspersky.Result)
	checkandaddtoresult("Malwarebytes", vtexeres.Data[0].Attributes.LastAnalysisResults.Malwarebytes.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.Malwarebytes.Result)
	checkandaddtoresult("McAfee", vtexeres.Data[0].Attributes.LastAnalysisResults.McAfee.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.McAfee.Result)
	checkandaddtoresult("McAfeeGWEd", vtexeres.Data[0].Attributes.LastAnalysisResults.McAfeeGWEdition.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.McAfeeGWEdition.Result)
	checkandaddtoresult("Sophos", vtexeres.Data[0].Attributes.LastAnalysisResults.Sophos.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.Sophos.Result)
	checkandaddtoresult("Symantec", vtexeres.Data[0].Attributes.LastAnalysisResults.Symantec.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.Symantec.Result)
	checkandaddtoresult("TrendMicro", vtexeres.Data[0].Attributes.LastAnalysisResults.TrendMicro.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.TrendMicro.Result)
	checkandaddtoresult("ZoneAlarm", vtexeres.Data[0].Attributes.LastAnalysisResults.ZoneAlarm.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.ZoneAlarm.Result)

}
