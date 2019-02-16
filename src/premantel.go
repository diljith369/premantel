package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"text/template"

	"./avcaesar"
	"./commonfeeds"
	"./cybercure"
	"./cymonio"
	"./ibmxforce"
	"./jotti"
	"./metadefender"
	"./safebrowse"
	"./shadowserver"
	"./shodan"
	"./threatintelstructs"
	"./urlquerynet"
	"./virustotal"
)

var malwscantmpl, hashsearchtmpl, icosearchtmpl, commonfeedtmpl, abouttmpl *template.Template
var apikeys threatintelstructs.APIs

var commonipfeeds threatintelstructs.IPFeeds
var commondnsfeeds threatintelstructs.DomainFeeds

type ScanResults struct {
	Vtscanres                map[string]string
	VtUploadedFileInfo       map[string]string
	Jottiscanres             map[string]string
	MetaScanres              map[string]string
	AvCaesorAVEngineResult   map[string]string
	AvCaesorAVFileInfoResult map[string]string
	CymonIpInfo              map[string]struct {
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

	GoogleSafeBrowse       map[string][]string
	Urlquerynetsearch      map[string]string
	ShadowServer           map[string]string
	IBMxForceMalwareReport map[string]string
	IBMxFroceIPReport      map[string]struct {
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
	CommonFeeds     map[string]string
	ShodanResult    map[string]string
	CybercureResult map[string]string
}

var scanResultStructForTemplate ScanResults

func init() {
	malwscantmpl = template.Must(template.ParseFiles("./templates/malwscan.html"))
	hashsearchtmpl = template.Must(template.ParseFiles("./templates/hashsearch.html"))
	icosearchtmpl = template.Must(template.ParseFiles("./templates/iocsearch.html"))
	commonfeedtmpl = template.Must(template.ParseFiles("./templates/commonfeeds.html"))
	abouttmpl = template.Must(template.ParseFiles("./templates/about.html"))
	apikeys = threatintelstructs.APIs{}
	commonipfeeds = threatintelstructs.IPFeeds{}
	commondnsfeeds = threatintelstructs.DomainFeeds{}
	scanResultStructForTemplate = ScanResults{}
	scanResultStructForTemplate.Jottiscanres = make(map[string]string)
	scanResultStructForTemplate.Vtscanres = make(map[string]string)
	scanResultStructForTemplate.VtUploadedFileInfo = make(map[string]string)
	scanResultStructForTemplate.MetaScanres = make(map[string]string)
	scanResultStructForTemplate.AvCaesorAVEngineResult = make(map[string]string)
	scanResultStructForTemplate.AvCaesorAVFileInfoResult = make(map[string]string)
	scanResultStructForTemplate.CymonIpInfo = make(map[string]struct {
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
	})
	scanResultStructForTemplate.IBMxFroceIPReport = make(map[string]struct {
		CreatedDate        string
		Reason             string
		Company            string
		CIDR               string
		Country            string
		CategoryType       string
		CategoryDescripton string
		ReasonDescription  string
		IP                 string
	})
	scanResultStructForTemplate.GoogleSafeBrowse = make(map[string][]string)
	scanResultStructForTemplate.Urlquerynetsearch = make(map[string]string)
	scanResultStructForTemplate.ShadowServer = make(map[string]string)
	scanResultStructForTemplate.IBMxForceMalwareReport = make(map[string]string)
	scanResultStructForTemplate.CommonFeeds = make(map[string]string)
	scanResultStructForTemplate.ShodanResult = make(map[string]string)
	scanResultStructForTemplate.CybercureResult = make(map[string]string)
}
func fillcommonfeeds() {
	ipfeedfile, err := ioutil.ReadFile("./commonfeeds/ipfeeds.cfg")
	if err != nil {
		fmt.Println(err)
	}
	//fmt.Println(string(ipfeedfile))
	err = json.Unmarshal(ipfeedfile, &commonipfeeds)

	if err != nil {
		fmt.Println(err)
	}

	domainfeedfile, err := ioutil.ReadFile("./commonfeeds/domainfeeds.cfg")
	if err != nil {
		fmt.Println(err)
	}
	err = json.Unmarshal(domainfeedfile, &commondnsfeeds)
	if err != nil {
		fmt.Println(err)
	}
}
func fillapikeys() {
	apifile, err := ioutil.ReadFile("./config/apiconfig.cfg")
	if err != nil {
		fmt.Println(err)
	}
	err = json.Unmarshal(apifile, &apikeys)
	if err != nil {
		fmt.Println(err)
	}

}

func clearhistory(clearmap map[string]string) {
	for k := range clearmap {
		delete(clearmap, k)
	}

}

func clearsafebrosehistory(clearmap map[string][]string) {
	for k := range clearmap {
		delete(clearmap, k)
	}

}

func hashsearch(httpwr http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		err := hashsearchtmpl.Execute(httpwr, nil)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		err := req.ParseForm()
		if err != nil {
			fmt.Println(err)
		}
		searchval := req.Form.Get("search")
		//filepath := req.Form.Get("filepath")
		//fmt.Println("path " + searchval)

		if strings.Compare(strings.TrimSpace(searchval), "") != 0 {

			clearhistory(scanResultStructForTemplate.Vtscanres)
			clearhistory(scanResultStructForTemplate.VtUploadedFileInfo)
			clearsafebrosehistory(scanResultStructForTemplate.GoogleSafeBrowse)
			clearhistory(scanResultStructForTemplate.Urlquerynetsearch)
			clearhistory(scanResultStructForTemplate.ShadowServer)
			clearhistory(scanResultStructForTemplate.IBMxForceMalwareReport)

			//vtResult = vtResult[:0]
			//vtResult = vtScanner(strings.TrimSpace(searchval))
			if strings.Index(searchval, "http") == 0 {
				finflag := make(chan string)
				go urlquerynet.Urlquerynetsearch(searchval, scanResultStructForTemplate.Urlquerynetsearch, finflag)
				go safebrowse.Getgooglesafebrowseresult(searchval, apikeys.Safebrowse, scanResultStructForTemplate.GoogleSafeBrowse, finflag)
				go virustotal.VtURLScanner(strings.TrimSpace(searchval), scanResultStructForTemplate.Vtscanres, finflag)
				<-finflag
				<-finflag
				<-finflag

			} else {
				finflag := make(chan string)
				//fmt.Println(searchval + "inside hash")
				//go vtexescanprocess(finflag)
				go virustotal.VtExeScanner(strings.TrimSpace(searchval), scanResultStructForTemplate.Vtscanres, scanResultStructForTemplate.VtUploadedFileInfo, finflag)
				go ibmxforce.XchangeMalwareHashReport(strings.TrimSpace(searchval), apikeys.IBMxForceKey, apikeys.IBMxForcePass, scanResultStructForTemplate.IBMxForceMalwareReport, finflag)
				go shadowserver.Shadowserversearch(strings.TrimSpace(searchval), scanResultStructForTemplate.ShadowServer, finflag)
				<-finflag
				<-finflag
				<-finflag

			}

			/*for k, v := range scanResultStructForTemplate.Vtscanres{
				 fmt.Printf("%s\t\t%s\n ", k,v)
			 }*/
			err := hashsearchtmpl.Execute(httpwr, scanResultStructForTemplate)
			if err != nil {
				fmt.Println(err)
			}

		}

	}
}

func malwscan(httpwr http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		err := malwscantmpl.Execute(httpwr, nil)
		if err != nil {
			fmt.Println(err)
		}
	} else {

		clearhistory(scanResultStructForTemplate.Jottiscanres)
		clearhistory(scanResultStructForTemplate.AvCaesorAVFileInfoResult)
		clearhistory(scanResultStructForTemplate.AvCaesorAVEngineResult)
		clearhistory(scanResultStructForTemplate.MetaScanres)
		err := req.ParseForm()
		file, handler, err := req.FormFile("upfile")
		if err != nil {
			fmt.Println(err)
			return
		}
		defer file.Close()
		filename := handler.Filename
		if strings.Compare(strings.TrimSpace(filename), "") != 0 {

			f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0666)
			if err != nil {
				fmt.Println(err)
				return
			}
			defer f.Close()

			io.Copy(f, file)
			if err != nil {
				fmt.Println(err)
			}
			finflag := make(chan string)

			go jotti.Jottiscanprocess(file, filename, finflag, apikeys.Jotti, scanResultStructForTemplate.Jottiscanres)
			go avcaesar.Uploadfiletoavcaesar(filename, finflag, scanResultStructForTemplate.AvCaesorAVFileInfoResult, scanResultStructForTemplate.AvCaesorAVEngineResult)
			go metadefender.Metadefenderfilescan(filename, finflag, apikeys.Metadefender, scanResultStructForTemplate.MetaScanres)
			//time.Sleep(6000 * time.Millisecond)
			<-finflag
			<-finflag
			<-finflag

			err = malwscantmpl.Execute(httpwr, scanResultStructForTemplate)
			if err != nil {
				fmt.Println(err)
			}
		}

	}

}

func iocsearch(httpwr http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		err := icosearchtmpl.Execute(httpwr, nil)
		if err != nil {
			fmt.Println(err)
		}
	} else {

		for k := range scanResultStructForTemplate.CymonIpInfo {
			delete(scanResultStructForTemplate.CymonIpInfo, k)
		}
		//clear values
		for k := range scanResultStructForTemplate.IBMxFroceIPReport {
			delete(scanResultStructForTemplate.IBMxFroceIPReport, k)
		}

		clearhistory(scanResultStructForTemplate.CommonFeeds)
		clearhistory(scanResultStructForTemplate.ShodanResult)
		clearhistory(scanResultStructForTemplate.CybercureResult)

		err := req.ParseForm()
		if err != nil {
			fmt.Println(err)
		}
		searchIPDomain := strings.TrimSpace(req.Form.Get("iocsearch"))
		validIP := regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
		isIP := validIP.MatchString(searchIPDomain)

		finflag := make(chan string)
		go cymonio.Getcymoniotoken(apikeys.CymonUser, apikeys.CymonPassword, finflag)
		<-finflag
		go cymonio.Getdetailsfromcymon(finflag, isIP, searchIPDomain, scanResultStructForTemplate.CymonIpInfo)
		<-finflag
		if isIP {
			go shodan.ShodanSearch(searchIPDomain, apikeys.Shodan, scanResultStructForTemplate.ShodanResult, finflag)
			<-finflag
			go cybercure.CybercureResult(searchIPDomain, scanResultStructForTemplate.CybercureResult, finflag)
			<-finflag
			go ibmxforce.XchangeIPReport(searchIPDomain, apikeys.IBMxForceKey, apikeys.IBMxForcePass, scanResultStructForTemplate.IBMxFroceIPReport, finflag)
			<-finflag
			go commonfeeds.GetAnalysisresultFromKeyFile(searchIPDomain, commonipfeeds.SnortIPFilter, scanResultStructForTemplate.CommonFeeds, "SnortIPFilter", finflag)
			<-finflag
			go commonfeeds.GetAnalysisresultFromKeyFile(searchIPDomain, commonipfeeds.SuricataCompromised, scanResultStructForTemplate.CommonFeeds, "SuricataCompromised", finflag)
			<-finflag
			go commonfeeds.GetAnalysisresultFromKeyFile(searchIPDomain, commonipfeeds.AlienvaultReputation, scanResultStructForTemplate.CommonFeeds, "AlienvaultReputation", finflag)
			<-finflag
			go commonfeeds.GetAnalysisresultFromKeyFile(searchIPDomain, commonipfeeds.SuricataBotCC, scanResultStructForTemplate.CommonFeeds, "SuricataBotCC", finflag)
			<-finflag
			go commonfeeds.GetAnalysisresultFromKeyFile(searchIPDomain, commonipfeeds.SurricataTor, scanResultStructForTemplate.CommonFeeds, "SurricataTor", finflag)
			<-finflag
			go commonfeeds.GetAnalysisresultFromKeyFile(searchIPDomain, commonipfeeds.MalwareDomainlistIP, scanResultStructForTemplate.CommonFeeds, "MalwareDomainlistIP", finflag)
			<-finflag
			go commonfeeds.GetAnalysisresultFromKeyFile(searchIPDomain, commonipfeeds.CiarmyBadIps, scanResultStructForTemplate.CommonFeeds, "CiarmyBadIps", finflag)
			<-finflag

		} else {
			go commonfeeds.GetAnalysisresultFromKeyFile(searchIPDomain, commondnsfeeds.MalwareDomainHosts, scanResultStructForTemplate.CommonFeeds, "MalwareDomainHosts", finflag)
			<-finflag
			go commonfeeds.GetAnalysisresultFromKeyFile(searchIPDomain, commondnsfeeds.MandiantAPT, scanResultStructForTemplate.CommonFeeds, "MandiantAPT", finflag)
			<-finflag

		}

		err = icosearchtmpl.Execute(httpwr, scanResultStructForTemplate)
		if err != nil {
			fmt.Println(err)
		}

	}
}

func about(httpwr http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		err := abouttmpl.Execute(httpwr, nil)
		if err != nil {
			fmt.Println(err)
		}
	}
}

func commonfeedsupdate(httpwr http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		err := commonfeedtmpl.Execute(httpwr, nil)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		err := req.ParseForm()
		if strings.Compare(strings.TrimSpace(req.Form.Get("updatecommonfeeds")), "updatecommonfeedsdb") == 0 {
			finflag := make(chan string)
			go commonfeeds.UpdateCommonDB(commonipfeeds.SnortIPFilter, "SnortIPFilter", finflag)
			<-finflag
			go commonfeeds.UpdateCommonDB(commonipfeeds.SuricataCompromised, "SuricataCompromised", finflag)
			<-finflag
			go commonfeeds.UpdateCommonDB(commonipfeeds.AlienvaultReputation, "AlienvaultReputation", finflag)
			<-finflag
			go commonfeeds.UpdateCommonDB(commonipfeeds.SuricataBotCC, "SuricataBotCC", finflag)
			<-finflag
			go commonfeeds.UpdateCommonDB(commonipfeeds.SurricataTor, "SurricataTor", finflag)
			<-finflag
			go commonfeeds.UpdateCommonDB(commonipfeeds.MalwareDomainlistIP, "MalwareDomainlistIP", finflag)
			<-finflag
			go commonfeeds.UpdateCommonDB(commonipfeeds.CiarmyBadIps, "CiarmyBadIps", finflag)
			<-finflag
			go commonfeeds.UpdateCommonDB(commondnsfeeds.MalwareDomainHosts, "MalwareDomainHosts", finflag)
			<-finflag
			go commonfeeds.UpdateCommonDB(commondnsfeeds.MandiantAPT, "MandiantAPT", finflag)
			<-finflag
			err = commonfeedtmpl.Execute(httpwr, nil)
			if err != nil {
				fmt.Println(err)
			}
		}
	}
}

func index(httpwr http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		err := malwscantmpl.Execute(httpwr, nil)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		err := req.ParseForm()
		if strings.Compare(strings.TrimSpace(req.Form.Get("updatecommonfeeds")), "updatecommonfeedsdb") == 0 {
			finflag := make(chan string)
			go commonfeeds.UpdateCommonDB(commonipfeeds.SnortIPFilter, "SnortIPFilter", finflag)
			<-finflag
			go commonfeeds.UpdateCommonDB(commonipfeeds.SuricataCompromised, "SuricataCompromised", finflag)
			<-finflag
			go commonfeeds.UpdateCommonDB(commonipfeeds.AlienvaultReputation, "AlienvaultReputation", finflag)
			<-finflag
			go commonfeeds.UpdateCommonDB(commonipfeeds.SuricataBotCC, "SuricataBotCC", finflag)
			<-finflag
			go commonfeeds.UpdateCommonDB(commonipfeeds.SurricataTor, "SurricataTor", finflag)
			<-finflag
			go commonfeeds.UpdateCommonDB(commonipfeeds.MalwareDomainlistIP, "MalwareDomainlistIP", finflag)
			<-finflag
			go commonfeeds.UpdateCommonDB(commonipfeeds.CiarmyBadIps, "CiarmyBadIps", finflag)
			<-finflag
			go commonfeeds.UpdateCommonDB(commondnsfeeds.MalwareDomainHosts, "MalwareDomainHosts", finflag)
			<-finflag
			go commonfeeds.UpdateCommonDB(commondnsfeeds.MandiantAPT, "MandiantAPT", finflag)
			<-finflag
			err = malwscantmpl.Execute(httpwr, nil)
			if err != nil {
				fmt.Println(err)
			}
		} else {
			searchval := req.Form.Get("search")
			//filepath := req.Form.Get("filepath")
			//fmt.Println("path " + filepath)

			if strings.Compare(strings.TrimSpace(searchval), "") != 0 {

				clearhistory(scanResultStructForTemplate.Vtscanres)
				clearhistory(scanResultStructForTemplate.VtUploadedFileInfo)
				clearsafebrosehistory(scanResultStructForTemplate.GoogleSafeBrowse)
				clearhistory(scanResultStructForTemplate.Urlquerynetsearch)
				clearhistory(scanResultStructForTemplate.ShadowServer)
				clearhistory(scanResultStructForTemplate.IBMxForceMalwareReport)

				//vtResult = vtResult[:0]
				//vtResult = vtScanner(strings.TrimSpace(searchval))
				if strings.Index(searchval, "http") == 0 {
					finflag := make(chan string)
					go urlquerynet.Urlquerynetsearch(searchval, scanResultStructForTemplate.Urlquerynetsearch, finflag)
					go safebrowse.Getgooglesafebrowseresult(searchval, apikeys.Safebrowse, scanResultStructForTemplate.GoogleSafeBrowse, finflag)
					go virustotal.VtURLScanner(strings.TrimSpace(searchval), scanResultStructForTemplate.Vtscanres, finflag)
					<-finflag
					<-finflag
					<-finflag

				} else {
					finflag := make(chan string)
					//go vtexescanprocess(finflag)
					go virustotal.VtExeScanner(strings.TrimSpace(searchval), scanResultStructForTemplate.Vtscanres, scanResultStructForTemplate.VtUploadedFileInfo, finflag)
					go ibmxforce.XchangeMalwareHashReport(strings.TrimSpace(searchval), apikeys.IBMxForceKey, apikeys.IBMxForcePass, scanResultStructForTemplate.IBMxForceMalwareReport, finflag)
					go shadowserver.Shadowserversearch(strings.TrimSpace(searchval), scanResultStructForTemplate.ShadowServer, finflag)
					<-finflag
					<-finflag
					<-finflag

				}

				/*for k, v := range scanResultStructForTemplate.Vtscanres{
					 fmt.Printf("%s\t\t%s\n ", k,v)
				 }*/
				err = malwscantmpl.Execute(httpwr, scanResultStructForTemplate)
				if err != nil {
					fmt.Println(err)
				}
			} else if strings.Compare(strings.TrimSpace(req.Form.Get("iocsearch")), "") != 0 {
				//clear values
				for k := range scanResultStructForTemplate.CymonIpInfo {
					delete(scanResultStructForTemplate.CymonIpInfo, k)
				}
				//clear values
				for k := range scanResultStructForTemplate.IBMxFroceIPReport {
					delete(scanResultStructForTemplate.IBMxFroceIPReport, k)
				}

				clearhistory(scanResultStructForTemplate.CommonFeeds)
				searchIPDomain := strings.TrimSpace(req.Form.Get("iocsearch"))
				validIP := regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
				isIP := validIP.MatchString(searchIPDomain)

				finflag := make(chan string)
				go cymonio.Getcymoniotoken(apikeys.CymonUser, apikeys.CymonPassword, finflag)
				<-finflag
				go cymonio.Getdetailsfromcymon(finflag, isIP, searchIPDomain, scanResultStructForTemplate.CymonIpInfo)
				<-finflag
				fmt.Println("ip search shodan")

				if isIP {
					fmt.Println("get shodan")
					go shodan.ShodanSearch(searchIPDomain, apikeys.Shodan, scanResultStructForTemplate.ShodanResult, finflag)
					<-finflag
					go ibmxforce.XchangeIPReport(searchIPDomain, apikeys.IBMxForceKey, apikeys.IBMxForcePass, scanResultStructForTemplate.IBMxFroceIPReport, finflag)
					<-finflag
					go commonfeeds.GetAnalysisresultFromKeyFile(searchIPDomain, commonipfeeds.SnortIPFilter, scanResultStructForTemplate.CommonFeeds, "SnortIPFilter", finflag)
					<-finflag
					go commonfeeds.GetAnalysisresultFromKeyFile(searchIPDomain, commonipfeeds.SuricataCompromised, scanResultStructForTemplate.CommonFeeds, "SuricataCompromised", finflag)
					<-finflag
					go commonfeeds.GetAnalysisresultFromKeyFile(searchIPDomain, commonipfeeds.AlienvaultReputation, scanResultStructForTemplate.CommonFeeds, "AlienvaultReputation", finflag)
					<-finflag
					go commonfeeds.GetAnalysisresultFromKeyFile(searchIPDomain, commonipfeeds.SuricataBotCC, scanResultStructForTemplate.CommonFeeds, "SuricataBotCC", finflag)
					<-finflag
					go commonfeeds.GetAnalysisresultFromKeyFile(searchIPDomain, commonipfeeds.SurricataTor, scanResultStructForTemplate.CommonFeeds, "SurricataTor", finflag)
					<-finflag
					go commonfeeds.GetAnalysisresultFromKeyFile(searchIPDomain, commonipfeeds.MalwareDomainlistIP, scanResultStructForTemplate.CommonFeeds, "MalwareDomainlistIP", finflag)
					<-finflag
					go commonfeeds.GetAnalysisresultFromKeyFile(searchIPDomain, commonipfeeds.CiarmyBadIps, scanResultStructForTemplate.CommonFeeds, "CiarmyBadIps", finflag)
					<-finflag

				} else {
					go commonfeeds.GetAnalysisresultFromKeyFile(searchIPDomain, commondnsfeeds.MalwareDomainHosts, scanResultStructForTemplate.CommonFeeds, "MalwareDomainHosts", finflag)
					<-finflag
					go commonfeeds.GetAnalysisresultFromKeyFile(searchIPDomain, commondnsfeeds.MandiantAPT, scanResultStructForTemplate.CommonFeeds, "MandiantAPT", finflag)
					<-finflag

				}

				err = malwscantmpl.Execute(httpwr, scanResultStructForTemplate)
				if err != nil {
					fmt.Println(err)
				}

			} else {

				clearhistory(scanResultStructForTemplate.Jottiscanres)
				clearhistory(scanResultStructForTemplate.AvCaesorAVFileInfoResult)
				clearhistory(scanResultStructForTemplate.AvCaesorAVEngineResult)
				clearhistory(scanResultStructForTemplate.MetaScanres)

				file, handler, err := req.FormFile("upfile")
				if err != nil {
					fmt.Println(err)
					return
				}
				defer file.Close()
				filename := handler.Filename
				if strings.Compare(strings.TrimSpace(filename), "") != 0 {

					f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0666)
					if err != nil {
						fmt.Println(err)
						return
					}
					defer f.Close()

					io.Copy(f, file)
					if err != nil {
						fmt.Println(err)
					}
					finflag := make(chan string)

					go jotti.Jottiscanprocess(file, filename, finflag, apikeys.Jotti, scanResultStructForTemplate.Jottiscanres)
					go avcaesar.Uploadfiletoavcaesar(filename, finflag, scanResultStructForTemplate.AvCaesorAVFileInfoResult, scanResultStructForTemplate.AvCaesorAVEngineResult)
					go metadefender.Metadefenderfilescan(filename, finflag, apikeys.Metadefender, scanResultStructForTemplate.MetaScanres)
					//time.Sleep(6000 * time.Millisecond)
					<-finflag
					<-finflag
					<-finflag

					err = malwscantmpl.Execute(httpwr, scanResultStructForTemplate)
					if err != nil {
						fmt.Println(err)
					}
				}
			}
		}
	}

}

func main() {
	fillapikeys()
	fillcommonfeeds()
	http.HandleFunc("/", malwscan)
	http.HandleFunc("/hashsearch", hashsearch)
	http.HandleFunc("/iocsearch", iocsearch)
	http.HandleFunc("/commonfeeds", commonfeedsupdate)
	http.HandleFunc("/about", about)
	http.Handle("/static/css/", http.StripPrefix("/static/css/", http.FileServer(http.Dir("static/css"))))
	/*http.Handle("/fonts/", http.StripPrefix("/fonts/", http.FileServer(http.Dir("templates/fonts"))))
	http.Handle("/js/", http.StripPrefix("/js/", http.FileServer(http.Dir("templates/js"))))
	http.Handle("/vendor/", http.StripPrefix("/vendor/", http.FileServer(http.Dir("templates/vendor"))))*/
	http.ListenAndServe(":"+apikeys.AppPort, nil)
}
