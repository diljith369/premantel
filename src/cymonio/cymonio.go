package cymonio

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"../threatintelstructs"
)

var cymonauthtoken threatintelstructs.CymonAuthHead
var cymonIPResult threatintelstructs.CymonIPResult

type resulttoprint struct {
	Title       string
	Description string
	ReportedBy  string
	Tag         string
	URL         string
	Hostname    string
	Domain      string
	IP          string
	Country     string
	City        string
}

//Getcymoniotoken gets token
func Getcymoniotoken(cymonuser string, cymonpassword string, finflag chan string) {

	apiURL := "https://api.cymon.io/v2/auth/login"
	var jsonStr = []byte(`{"username":"usr","password":"pass"}`)

	jsonStr = []byte(strings.Replace(string(jsonStr), "usr", cymonuser, 1))
	jsonStr = []byte(strings.Replace(string(jsonStr), "pass", cymonpassword, 1))
	//Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}

	/*transport := http.Transport{}
	transport.Proxy = http.ProxyURL(proxyUrl)// set proxy
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //set ssl*/

	//if need to set proxy
	//proxyUrl, _ := url.Parse("http://127.0.0.1:8080")
	//client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl), TLSClientConfig:&tls.Config{InsecureSkipVerify: true }}}
	//r, _ := http.NewRequest("POST",urlstr,strings.NewReader(data.Encode()))
	client := &http.Client{}
	req, _ := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonStr))
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	body_byte, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	json.Unmarshal(body_byte, &cymonauthtoken)
	finflag <- "got token"
	//fmt.Println(cymonauthtoken.Jwt)
}

//Getdetailsfromcymon gets details from cymonio
func Getdetailsfromcymon(finflag chan string, isIP bool, searchval string, CymonIpInfo map[string]struct {
	Title       string
	Description string
	ReportedBy  string
	Tag         string
	URL         string
	Hostname    string
	Domain      string
	IP          string
	Country     string
	City        string
}) {

	var apiURL string
	if isIP {
		apiURL = "https://api.cymon.io/v2/ioc/search/ip/" + searchval
	} else {
		apiURL = "https://api.cymon.io/v2/ioc/search/domain/" + searchval
	}

	//Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}

	/*transport := http.Transport{}
	transport.Proxy = http.ProxyURL(proxyUrl)// set proxy
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //set ssl*/

	//if need to set proxy
	//proxyUrl, _ := url.Parse("http://127.0.0.1:8080")
	//client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl), TLSClientConfig:&tls.Config{InsecureSkipVerify: true }}}
	client := &http.Client{}
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Add("Authorization", cymonauthtoken.Jwt)

	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	body_byte, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	json.Unmarshal(body_byte, &cymonIPResult)

	var ipresult resulttoprint

	for index, ipInfo := range cymonIPResult.Hits {
		ipresult.Title = ipInfo.Title
		ipresult.Description = ipInfo.Description
		ipresult.ReportedBy = ipInfo.ReportedBy
		if len(ipInfo.Tags) > 0 {
			ipresult.Tag = ipInfo.Tags[0]
		}
		ipresult.URL = ipInfo.Ioc.URL
		ipresult.Hostname = ipInfo.Ioc.Hostname
		ipresult.IP = ipInfo.Ioc.IP
		ipresult.Country = ipInfo.Location.Country
		ipresult.City = ipInfo.Location.City
		ipresult.Domain = ipInfo.Ioc.Domain
		CymonIpInfo[string(index)] = ipresult
	}

	//fmt.Println(string(body_byte))
	finflag <- "got cymonresult"
}
