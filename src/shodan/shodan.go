package shodan

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"../threatintelstructs"
)

var shodanresult threatintelstructs.Shodan

//ShodanSearch
func ShodanSearch(searchval string, apikey string, ShodanScanResult map[string]string, finflag chan string) {
	var apiURL, ports string
	apiURL = "https://api.shodan.io/shodan/host/" + searchval

	client := &http.Client{}
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Add("Content-Type", "application/json")
	val := req.URL.Query()
	val.Add("key", apikey)
	req.URL.RawQuery = val.Encode()
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	bodybyte, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	json.Unmarshal(bodybyte, &shodanresult)
	//fmt.Println(shodanresult.CountryName)
	//fmt.Println(shodanresult.Os)
	ShodanScanResult["Country Name"] = shodanresult.CountryName
	ShodanScanResult["City Name"] = fmt.Sprintf("%v", shodanresult.City)

	ShodanScanResult["Operating System"] = fmt.Sprintf("%v", shodanresult.Os)
	if len(shodanresult.Data) > 0 {
		ShodanScanResult["Organisation Name"] = shodanresult.Data[0].Org
		ShodanScanResult["Product"] = shodanresult.Data[0].Product
		ShodanScanResult["Banner"] = shodanresult.Data[0].Banner

	}
	//fmt.Println(shodanresult.Data[0].Product)
	//fmt.Println(shodanresult.Data[0].Banner)
	var strports []string
	ports = ""

	for i := 0; i < len(shodanresult.Ports); i++ {
		intval := fmt.Sprintf("%d", shodanresult.Ports[i])
		strports = append(strports, intval)
	}
	ports = strings.Join(strports[:], ",")
	//fmt.Println(ports)
	ShodanScanResult["Ports"] = ports
	var honeypot string
	honeypot = "https://api.shodan.io/labs/honeyscore/" + searchval

	client = &http.Client{}
	req, _ = http.NewRequest("GET", honeypot, nil)
	req.Header.Add("Content-Type", "application/json")
	val = req.URL.Query()
	val.Add("key", apikey)
	req.URL.RawQuery = val.Encode()
	resp, err = client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	bodybyte, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	ShodanScanResult["Honeypot Score"] = (string(bodybyte))

	finflag <- "got shodan res"
}
