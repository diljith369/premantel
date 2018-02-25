package urlquerynet

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

//Urlquerynetsearch searches in urlquery.net
func Urlquerynetsearch(tosearch string, Urlquerynetsearch map[string]string, finflag chan string) {
	var mainurl string
	mainurl = "http://www.urlquery.net/search"
	req, _ := http.NewRequest("GET", mainurl, nil)
	qstring := req.URL.Query()
	qstring.Add("q", tosearch)
	req.URL.RawQuery = qstring.Encode()
	client := &http.Client{}
	resp, _ := client.Do(req)
	defer resp.Body.Close()
	doc, goqueryerr := goquery.NewDocumentFromResponse(resp)
	if goqueryerr != nil {
		fmt.Println(goqueryerr)
	}
	resultlink, _ := doc.Find("table tr td").Find("a").Attr("href")

	mainlink, _ := url.ParseRequestURI(mainurl)
	mainlink.Path = resultlink
	//fmt.Printf("Main link : %s \n",mainlink.String())
	newreq, _ := http.NewRequest("GET", mainlink.String(), nil)
	client2 := &http.Client{}
	newresp, _ := client2.Do(newreq)
	defer newresp.Body.Close()
	//bodybyte , _ := ioutil.ReadAll(newresp.Body)
	//fmt.Println(string(bodybyte))

	doc2, goqueryerr2 := goquery.NewDocumentFromResponse(newresp)
	if goqueryerr2 != nil {
		fmt.Println(goqueryerr)
	}
	doc2.Find("table tbody tr").Each(func(index int, item *goquery.Selection) {

		key := strings.TrimSpace(item.Find(".odd_heading").Text())
		//fmt.Printf("Key val is %s", key)
		switch key {
		case "ASN", "Pool", "Report completed":
			key = ""
		}

		if strings.Contains(key, "Access Level") || strings.Contains(key, "Referer") || strings.Contains(key, "Status") {
			key = ""
		}

		val := item.Find(".odd_heading").Next().Text()

		if key != "" {
			//fmt.Printf("Key  : %s\t\tValue : %s \n", key, val)
			if strings.Contains(key, "Fortinet") || strings.Contains(key, "Suricata") || strings.Contains(key, "OpenPhish") &&
				!strings.Contains(val, "No alerts detected") {
				val = item.Find(".odd_heading").Next().Find("table tbody").Find("tr").Find("td").Last().Text()
			}
			Urlquerynetsearch[key] = strings.TrimSpace(val)
		}

		key = strings.TrimSpace(item.Find(".even_heading").Text())
		val = item.Find(".even_heading").Next().Text()
		if key != "" {
			//fmt.Printf("Key  : %s\t\tValue : %s \n", key, val)
			val = strings.TrimRight(val, "\n\r")
			Urlquerynetsearch[key] = strings.TrimSpace(val)
		}
	})

	for k := range Urlquerynetsearch {
		if strings.Contains(k, "Access Level") || strings.Contains(k, "Referer") || strings.Contains(k, "Status") {
			delete(Urlquerynetsearch, k)
		}
	}

	finflag <- "finsihed urlquery.net"
	/*for k, v := range   Urlquerynetsearch {
		fmt.Printf("%s\t\t%s\n",k, v)
	}*/
}
