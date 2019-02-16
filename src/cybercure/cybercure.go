package cybercure

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"../threatintelstructs"
)

var cybercureresult threatintelstructs.Cybercure

//CybercureResult(searchval string)
func CybercureResult(searchval string, CybsercureScanResult map[string]string, finflag chan string) {
	var apiURL, urls string
	urls = ""
	apiURL = "http://api.cybercure.ai/feed/search"

	client := &http.Client{}
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Add("Content-Type", "application/json")
	val := req.URL.Query()
	val.Add("value", searchval)
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
	json.Unmarshal(bodybyte, &cybercureresult)
	if cybercureresult.Exists {
		//fmt.Println(cybercureresult.Details.LastSighting.TargetedCountry)
		CybsercureScanResult["Targeted Country"] = (cybercureresult.Details.LastSighting.TargetedCountry)
		CybsercureScanResult["Targeted Segment"] = (cybercureresult.Details.LastSighting.TargetedSegment)

		urls = strings.Join(cybercureresult.Details.LastSighting.AssociatedUrls[:], "\n")
		/*for i := 0; i < len(cybercureresult.Details.LastSighting.AssociatedUrls); i++ {
			strurls =  strings.Join(cybercureresult.Details.LastSighting.AssociatedUrls[i], "\n")
		}*/
		CybsercureScanResult["URLs"] = urls
	}

	finflag <- "cybercure finished"

}
