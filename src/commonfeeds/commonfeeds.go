package commonfeeds

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

var (
	err error
)

//GetAnalysisresult gets results after analysing ip or domain
func GetAnalysisresult(search string, urltosearch string, scanresult map[string]string, key string, finflag chan string) {

	client := &http.Client{}
	req, _ := http.NewRequest("GET", urltosearch, nil)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	bodybyte, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	res := string(bodybyte)

	if strings.Contains(res, search) {
		scanresult[key] = "Malicious"
	} else {
		scanresult[key] = ""
	}
	finflag <- "done!"
}

//GetAnalysisresultFromKeyFile opens db flat file according to key and returns result
func GetAnalysisresultFromKeyFile(search string, urltosearch string, scanresult map[string]string, key string, finflag chan string) {

	fpath := "./commonfeeds/db/" + key
	resbytes, _ := ioutil.ReadFile(fpath)
	if err != nil {
		fmt.Println(err)
	}
	res := string(resbytes)

	if strings.Contains(res, search) {
		scanresult[key] = "Malicious"
	} else {
		scanresult[key] = ""
	}
	finflag <- "done!"
}

//UpdateCommonDB method will create flat db files for common feeds update
func UpdateCommonDB(urltosearch string, key string, finflag chan string) {

	client := &http.Client{}
	req, _ := http.NewRequest("GET", urltosearch, nil)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	bodybyte, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	//res := string(bodybyte)
	fpath := "./commonfeeds/db/" + key
	op, err := os.Create(fpath)
	defer op.Close()
	if err != nil {
		fmt.Println("Error while updating CommonDB : DB file generation failed")
	}
	op.Write(bodybyte)
	finflag <- "done!"
}
