package metadefender

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"../threatintelstructs"
)

var metascanResult threatintelstructs.MetaDefenderScanResult
var metascanDataID threatintelstructs.MetaDefenderDataID

//Metadefenderfilescan uploads and scans files
func Metadefenderfilescan(filename string, finflag chan string, apikey string, MetaScanres map[string]string) {

	fh, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
	}
	defer fh.Close()
	bodybuff := &bytes.Buffer{}
	bodywriter := multipart.NewWriter(bodybuff)

	filewriter, err := bodywriter.CreateFormFile("file", filepath.Base(filename))
	if err != nil {
		fmt.Println("error writing to file")
	}
	_, err = io.Copy(filewriter, fh)
	if err != nil {
		fmt.Println(err)
	}

	bodywriter.Close()
	scanreq, scanreqerr := http.NewRequest("POST", "https://api.metadefender.com/v2/file", bodybuff)
	if scanreqerr != nil {
		fmt.Println(scanreqerr)
	}
	scanreq.Header.Add("apikey", apikey)
	scanreq.Header.Add("Content-Type", bodywriter.FormDataContentType())

	client := &http.Client{}
	//fmt.Println("Uploading .........metadefender")
	resp, uploaderr := client.Do(scanreq)
	if uploaderr != nil {
		fmt.Println(uploaderr)
	}
	//fmt.Println("metadefender .........Done!")
	defer resp.Body.Close()

	respBodyBytes, _ := ioutil.ReadAll(resp.Body)
	//fmt.Println(string(respBodyBytes))
	_ = json.Unmarshal(respBodyBytes, &metascanDataID)
	//fmt.Println(metascanDataID.DataID)
	time.Sleep(6000 * time.Millisecond)
	fillScanResult(metascanDataID.DataID, apikey, MetaScanres)
	finflag <- "finishedmetadef"

}

func getmetadefenderfilescanresult(dataid string, apikey string) []byte {
	//https://api.metadefender.com/v2/file/+dataid
	scanreq, dataiderr := http.NewRequest("GET", "https://api.metadefender.com/v2/file/"+dataid, nil)
	scanreq.Header.Add("apikey", apikey)
	if dataiderr != nil {
		fmt.Println(dataiderr)
	}
	client := &http.Client{}
	resp, uploaderr := client.Do(scanreq)
	if uploaderr != nil {
		fmt.Println(uploaderr)
	}
	defer resp.Body.Close()

	//fmt.Println("scan result")
	respBodyBytes, _ := ioutil.ReadAll(resp.Body)
	//fmt.Println(string(respBodyBytes))
	return respBodyBytes

}

//FillScanResult fills result for html output
func fillScanResult(dataid string, apikey string, MetaScanres map[string]string) {
	metadefreserr := json.Unmarshal(getmetadefenderfilescanresult(dataid, apikey), &metascanResult)
	if metadefreserr != nil {
		fmt.Println(metadefreserr)
	}
	metadefenderscanprocess(MetaScanres)
}

//parmas removed for testing {file multipart.File, filename string}
func metadefenderscanprocess(MetaScanres map[string]string) {

	/*datascaniderr := json.Unmarshal(metadefenderfilescan(file,filename),&metascanDataId )
	if datascaniderr != nil {
		fmt.Println(datascaniderr)
	}
	time.Sleep(4000 * time.Millisecond)
	fmt.Printf("Data ID : %s", metascanDataId.DataID)
	metadefreserr := json.Unmarshal(getmetadefenderfilescanresult(metascanDataId.DataID),&metascanResult)
	if metadefreserr != nil {
		fmt.Println(metadefreserr)
	}*/

	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.Antiy.ThreatFound) != "" {
		MetaScanres["Antiy"] = metascanResult.ScanResults.ScanDetails.Antiy.ThreatFound
	}
	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.TrendMicro.ThreatFound) != "" {
		MetaScanres["TrendMicro"] = metascanResult.ScanResults.ScanDetails.TrendMicro.ThreatFound
	}
	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.BitDefender.ThreatFound) != "" {
		MetaScanres["BitDefender"] = metascanResult.ScanResults.ScanDetails.BitDefender.ThreatFound
	}
	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.AVG.ThreatFound) != "" {
		MetaScanres["AVG"] = metascanResult.ScanResults.ScanDetails.AVG.ThreatFound
	}
	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.CYREN.ThreatFound) != "" {
		MetaScanres["Cyren"] = metascanResult.ScanResults.ScanDetails.CYREN.ThreatFound
	}
	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.Fortinet.ThreatFound) != "" {
		MetaScanres["Fortinet"] = metascanResult.ScanResults.ScanDetails.Fortinet.ThreatFound
	}
	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.Ikarus.ThreatFound) != "" {
		MetaScanres["Ikarus"] = metascanResult.ScanResults.ScanDetails.Ikarus.ThreatFound
	}
	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.K7.ThreatFound) != "" {
		MetaScanres["K7"] = metascanResult.ScanResults.ScanDetails.K7.ThreatFound
	}
	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.McAfee.ThreatFound) != "" {
		MetaScanres["McAfee"] = metascanResult.ScanResults.ScanDetails.McAfee.ThreatFound
	}
	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.QuickHeal.ThreatFound) != "" {
		MetaScanres["QuickHeal"] = metascanResult.ScanResults.ScanDetails.QuickHeal.ThreatFound
	}
	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.Sophos.ThreatFound) != "" {
		MetaScanres["Sophos"] = metascanResult.ScanResults.ScanDetails.Sophos.ThreatFound
	}
	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.TotalDefense.ThreatFound) != "" {
		MetaScanres["TotalDefense"] = metascanResult.ScanResults.ScanDetails.TotalDefense.ThreatFound
	}
	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.Symantec.ThreatFound) != "" {
		MetaScanres["Symantec"] = metascanResult.ScanResults.ScanDetails.Symantec.ThreatFound
	}
	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.ThreatTrack.ThreatFound) != "" {
		MetaScanres["ThreatTrack"] = metascanResult.ScanResults.ScanDetails.ThreatTrack.ThreatFound
	}
}
