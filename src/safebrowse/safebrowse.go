package safebrowse

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"../threatintelstructs"
)

var googlesafebrowse threatintelstructs.GoogleSafeBrowsing

//Getgooglesafebrowseresult for html display
func Getgooglesafebrowseresult(urltosearch string, apikey string, GoogleSafeBrowse map[string][]string, finflag chan string) {

	query := "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + apikey

	var jsonStr = []byte(`{
    "client": {
      "clientId":      "threatintel",
      "clientVersion": "1.5.2"
    },
    "threatInfo": {
      "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING"],
      "platformTypes":    ["WINDOWS"],
      "threatEntryTypes": ["URL"],
      "threatEntries": [
        {"url": "replace"}
      ]
    }
  }`)

	jsonStr = []byte(strings.Replace(string(jsonStr), "replace", urltosearch, 1))

	client := &http.Client{}
	req, _ := http.NewRequest("POST", query, bytes.NewBuffer(jsonStr))
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
	googlesafebrowse = threatintelstructs.GoogleSafeBrowsing{}
	err = json.Unmarshal(body_byte, &googlesafebrowse)
	if err != nil {
		fmt.Println(err)
	}

	if len(googlesafebrowse.Matches) > 0 {
		GoogleSafeBrowse["SafeBrowse"] = []string{googlesafebrowse.Matches[0].ThreatType, googlesafebrowse.Matches[0].PlatformType, googlesafebrowse.Matches[0].Threat.URL}
	}

	finflag <- "finished safebrowse"
}
