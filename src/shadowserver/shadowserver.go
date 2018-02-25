package shadowserver

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

//Shadowserversearch searches hashes in shadow server
func Shadowserversearch(searchval string, ShadowServer map[string]string, finflag chan string) {
	avresult := make(map[string]string)
	client := &http.Client{}
	req, err := http.NewRequest("GET", "http://innocuous.shadowserver.org/api/", nil)
	if err != nil {
		fmt.Println(err)
	}
	qstring := req.URL.Query()
	qstring.Add("query", searchval)
	req.URL.RawQuery = qstring.Encode()
	resp, err3 := client.Do(req)
	if err3 != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	bodybyte, err2 := ioutil.ReadAll(resp.Body)
	if err2 != nil {
		fmt.Println(err)
	}
	var resultstring string
	resultstring = string(bodybyte)
	finalarray := strings.Split(resultstring, "\n")
	if len(finalarray) > 0 {
		for i := range finalarray {
			if strings.Index(finalarray[i], "{") == 0 {
				avresult[strconv.Itoa(i)] = finalarray[i]
				//fmt.Println((finalarray[i]))
			}
		}
		for k := range avresult {
			if strings.Contains(avresult[k], ":") {
				ShadowServer[(strings.Replace(strings.Replace(strings.Split(avresult[k], ":")[0], "\"", "", 2), "{", "", 1))] = (strings.Replace(strings.Replace(strings.Split(avresult[k], ":")[1], "\"", "", 2), "}", "", 1))
			}
		}
	}

	finflag <- "finished shadow server"
}
