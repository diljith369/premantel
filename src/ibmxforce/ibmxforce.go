package ibmxforce

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"

	"../threatintelstructs"
)

var ibmxforcemalwarereport threatintelstructs.IBMxForceMalware
var ibmxforceipreport threatintelstructs.IBMxFroceIPReport

//XchangeMalwareHashReport searches hashes and reuturns results
func XchangeMalwareHashReport(searchval string, ibmapikey string, ibmapipass string, IBMxForceMalwareReport map[string]string, finflag chan string) {

	apiurl := "https://api.xforce.ibmcloud.com/"
	malwareresouce := "/malware/" + searchval
	finalurl, _ := url.ParseRequestURI(apiurl)
	finalurl.Path = malwareresouce
	urltosearch := finalurl.String()
	//fmt.Println(urltosearch)
	req, _ := http.NewRequest("GET", urltosearch, nil)
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(ibmapikey, ibmapipass)
	ibmclient := &http.Client{}
	resp, _ := ibmclient.Do(req)
	defer resp.Body.Close()
	resp_body_byte, _ := ioutil.ReadAll(resp.Body)
	//fmt.Println(string(resp_body_byte))

	ibmxforcemalwarereport = threatintelstructs.IBMxForceMalware{}
	var malwarefamily string
	var malwarefamilies []string
	json.Unmarshal(resp_body_byte, &ibmxforcemalwarereport)
	//scanResultStructForTemplate.IBMxForceMalwareReport["Detection Coverage"] = strconv.Itoa(ibmxforcemalwarereport.Malware.Origins.External.DetectionCoverage)
	malwarefamilies = ibmxforcemalwarereport.Malware.Origins.External.Family
	if len(malwarefamilies) == 1 {
		IBMxForceMalwareReport["MalwareFamily"] = malwarefamilies[0]
	} else if len(malwarefamilies) > 1 {
		for i := range malwarefamilies {
			//fmt.Println(malwarefamilies[i])
			malwarefamily += malwarefamilies[i] + ","
		}
	}
	IBMxForceMalwareReport["MalwareFamily"] = malwarefamily
	IBMxForceMalwareReport["Risk"] = ibmxforcemalwarereport.Malware.Risk
	/*for k, v := range scanResultStructForTemplate.IBMxForceMalwareReport {
		fmt.Printf("%s --- %s", scanResultStructForTemplate.IBMxForceMalwareReport[k], scanResultStructForTemplate.IBMxForceMalwareReport[v])
	}*/
	finflag <- "ibm malware search finished"
	//fmt.Println(string(resp_body_byte))

}

//XchangeIPReport searches IP and returns result
func XchangeIPReport(searchval string, ibmapikey string, ibmapipass string, IBMxFroceIPReport map[string]struct {
	CreatedDate        string
	Reason             string
	Company            string
	CIDR               string
	Country            string
	CategoryType       string
	CategoryDescripton string
	ReasonDescription  string
	IP                 string
}, finflag chan string) {

	apiurl := "https://api.xforce.ibmcloud.com/"
	//malwareresouce := "/malware/" + searchval
	ipreport := "/ipr/" + searchval
	//ipmalwarereport := "/ipr/malware/" + searchval
	finalurl, _ := url.ParseRequestURI(apiurl)
	finalurl.Path = ipreport
	urltosearch := finalurl.String()
	//fmt.Println(urltosearch)
	req, _ := http.NewRequest("GET", urltosearch, nil)
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(ibmapikey, ibmapipass)
	ibmclient := &http.Client{}
	resp, _ := ibmclient.Do(req)
	defer resp.Body.Close()
	resp_body_byte, _ := ioutil.ReadAll(resp.Body)
	ibmxforceipreport = threatintelstructs.IBMxFroceIPReport{}
	err := json.Unmarshal(resp_body_byte, &ibmxforceipreport)
	if err != nil {
		fmt.Println(err)
	}
	type ibmiphistory struct {
		CreatedDate        string
		Reason             string
		Company            string
		CIDR               string
		Country            string
		CategoryType       string
		CategoryDescripton string
		ReasonDescription  string
		IP                 string
	}

	var ipresult ibmiphistory

	for index, ipInfo := range ibmxforceipreport.History {
		ipresult.CreatedDate = ipInfo.Created.Format("2006-01-02 15:04:05")
		ipresult.Reason = ipInfo.Reason
		ipresult.Company = ipInfo.Asns.Num5048.Company
		ipresult.Country = ipInfo.Geo.Country
		ipresult.CIDR = strconv.Itoa(ipInfo.Asns.Num5048.Cidr)
		ipresult.IP = ipInfo.IP
		for k := range ipInfo.Cats {
			ipresult.CategoryType += k
		}
		for k, v := range ipInfo.CategoryDescriptions {
			ipresult.CategoryDescripton += k + ". " + v
		}
		ipresult.Reason = ipInfo.ReasonDescription
		IBMxFroceIPReport[strconv.Itoa(index)] = ipresult
	}

	for index, ipInfo := range ibmxforceipreport.Subnets {
		ipresult.CreatedDate = ipInfo.Created.Format("2006-01-02 15:04:05")
		ipresult.Reason = ipInfo.Reason
		ipresult.Company = ipInfo.Asns.Num5048.Company
		ipresult.Country = ipInfo.Geo.Country
		ipresult.CIDR = strconv.Itoa(ipInfo.Asns.Num5048.Cidr)
		for k := range ipInfo.Cats {
			ipresult.CategoryType += k
		}
		for k, v := range ipInfo.CategoryDescriptions {
			ipresult.CategoryDescripton += k + ". " + v
		}
		ipresult.Reason = ipInfo.ReasonDescription
		IBMxFroceIPReport[strconv.Itoa(index)] = ipresult
	}
	finflag <- "ibm ip report finished"
	//fmt.Println(string(resp_body_byte))

}
