package jotti

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"../threatintelstructs"
)

// uploadfiletojotti uploads to virusscanjotti
func uploadfiletojotti(filename string, desturl string, token string, apikey string) []byte {

	//fmt.Println("token " + token)
	fh, err := os.Open(filename)
	if err != nil {
		fmt.Println("error opening file")
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

	formfield, formfielderr := bodywriter.CreateFormField("scanToken")
	if formfielderr != nil {
		fmt.Println(err)
	}
	formfield.Write([]byte(token))

	bodywriter.Close()
	//contentType := bodywriter.FormDataContentType()

	req, err := http.NewRequest("POST", desturl, bodybuff)
	req.Header.Add("Authorization", "Key "+apikey)
	req.Header.Add("Accept", "application/vnd.filescanjob-api.v2+json")
	req.Header.Set("Content-Type", bodywriter.FormDataContentType())
	//proxyUrl, _ := url.Parse("http://127.0.0.1:8080")
	//client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl), TLSClientConfig:&tls.Config{InsecureSkipVerify: true }}}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	bodybyte, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	return bodybyte
}

//Jottiscanprocess scanning the uploaded file
func Jottiscanprocess(file multipart.File, filename string, finflag chan string, apikey string, Jottiscanres map[string]string) {

	jottitoken := threatintelstructs.JottiVirusScanToken{}
	err := json.Unmarshal(getjottifilescanjobid(apikey), &jottitoken)
	if err != nil {
		fmt.Println(err)
	}
	jottijobscanid := threatintelstructs.JottiVirusScanFileScanJobID{}
	errjobid := json.Unmarshal(uploadfiletojotti(strings.TrimSpace(filename), "https://virusscan.jotti.org/api/filescanjob/v2/createjob", jottitoken.ScanToken, apikey), &jottijobscanid)
	if errjobid != nil {
		fmt.Println(errjobid)
	}

	jottiScanResult := threatintelstructs.JottiVirusScanResult{}
	time.Sleep(4000 * time.Millisecond)
	errscanres := json.Unmarshal(getjottiscannedresult(jottijobscanid.FileScanJobID, apikey), &jottiScanResult)
	if errscanres != nil {
		fmt.Println(errscanres)
	}

	if len(jottiScanResult.ScanJob.ScannerResults) > 0 {
		for i := range jottiScanResult.ScanJob.ScannerResults {
			if strings.Compare(strings.TrimSpace(jottiScanResult.ScanJob.ScannerResults[i].MalwareName), "") > 0 {
				Jottiscanres[jottiScanResult.ScanJob.ScannerResults[i].ScannerName] = jottiScanResult.ScanJob.ScannerResults[i].MalwareName
			}
		}
	}
	finflag <- "finishedjotti"

}

func getjottifilescanjobid(apikey string) []byte {

	apiURL := "https://virusscan.jotti.org"
	resource := "/api/filescanjob/createscantoken"
	u, _ := url.ParseRequestURI(apiURL)
	u.Path = resource
	urlstr := u.String()
	//fmt.Println(urlstr)

	//Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}

	/*transport := http.Transport{}
	transport.Proxy = http.ProxyURL(proxyUrl)// set proxy
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //set ssl*/

	//if need to set proxy
	//proxyUrl, _ := url.Parse("http://127.0.0.1:8080")
	//client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl), TLSClientConfig:&tls.Config{InsecureSkipVerify: true }}}
	//r, _ := http.NewRequest("POST",urlstr,strings.NewReader(data.Encode()))
	client := &http.Client{}
	req, _ := http.NewRequest("POST", urlstr, nil)
	req.Header.Add("Authorization", "Key "+apikey)
	req.Header.Add("Accept", "application/vnd.filescanjob-api.v2+json")
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
	return body_byte
	//fmt.Println(string(body_byte))
}

func getjottiscannedresult(jobscanid string, apikey string) []byte {

	jobidurl := "https://virusscan.jotti.org/api/filescanjob/getjobstatus/" + jobscanid
	req, _ := http.NewRequest("GET", jobidurl, nil)
	req.Header.Add("Authorization", "Key "+apikey)
	req.Header.Add("Accept", "application/vnd.filescanjob-api.v2+json")
	req.Header.Add("Content-Type", "application/json")
	//proxyUrl, _ := url.Parse("http://127.0.0.1:8080")
	//client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl), TLSClientConfig:&tls.Config{InsecureSkipVerify: true }}}
	//fmt.Println(req.URL.String())
	client := &http.Client{}
	resp, err := client.Do(req)
	//resp, err := http.Get("https://www.virustotal.com/ui/search?query=cc5c1ceeabf310b66e750f3e7fa4e091&relationships[url]=network_location%2Clast_serving_ip_address&relationships[comment]=author%2Citem")
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	body_byte, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}

	return (body_byte)

}
func uploadfiletojottiusingmultipartformdata(filecontent multipart.File, filename string, desturl string, token string, apikey string) []byte {

	//fmt.Println("token " + token)
	/*fh, err := os.Open(filename)
	if err != nil {
		fmt.Println("error opening file")
	}
	defer fh.Close()*/
	bodybuff := &bytes.Buffer{}
	bodywriter := multipart.NewWriter(bodybuff)

	filewriter, err := bodywriter.CreateFormFile("file", filepath.Base(filename))
	if err != nil {
		fmt.Println("error writing to file")
	}
	_, err = io.Copy(filewriter, filecontent)
	if err != nil {
		fmt.Println(err)
	}

	formfield, formfielderr := bodywriter.CreateFormField("scanToken")
	if formfielderr != nil {
		fmt.Println(err)
	}
	formfield.Write([]byte(token))

	bodywriter.Close()
	//contentType := bodywriter.FormDataContentType()
	req, err := http.NewRequest("POST", desturl, bodybuff)
	req.Header.Add("Authorization", "Key "+apikey)
	req.Header.Add("Accept", "application/vnd.filescanjob-api.v2+json")
	req.Header.Set("Content-Type", bodywriter.FormDataContentType())
	//proxyUrl, _ := url.Parse("http://127.0.0.1:8080")
	//client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl), TLSClientConfig:&tls.Config{InsecureSkipVerify: true }}}
	client := &http.Client{}
	//fmt.Printf("Uploading Jotti.......")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	//fmt.Printf("............Jotti Done.\n")
	defer resp.Body.Close()
	body_byte, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	//fmt.Println("Jotti scan result is : \n")
	//fmt.Println(string(body_byte))
	return body_byte
}
