package avcaesar

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

//Uploadfiletoavcaesar uploading to avcaesar
func Uploadfiletoavcaesar(filename string, finflag chan string, AvCaesorAVFileInfoResult map[string]string, AvCaesorAVEngineResult map[string]string) {

	apiURL := "https://avcaesar.malware.lu/"
	resource := "/sample/upload"
	u, _ := url.ParseRequestURI(apiURL)
	u.Path = resource
	urlstr := u.String()
	//fmt.Println(urlstr)

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

	bodywriter.Close()

	req, err := http.NewRequest("POST", urlstr, bodybuff)
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Add("Accept-Language", "en-US,en;q=0.5")
	req.Header.Add("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Content-Type", bodywriter.FormDataContentType())

	//proxyUrl, _ := url.Parse("http://127.0.0.1:8080")
	//client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl), TLSClientConfig:&tls.Config{InsecureSkipVerify: true }}}
	//client := &http.Client{}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}

	//fmt.Printf("Uploading .......")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	//fmt.Printf("............Done.\n")
	//fmt.Printf("Status Code : . %d\n",resp.StatusCode)
	defer resp.Body.Close()
	body_byte, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}

	if err != nil {
		fmt.Println(err)
	}

	finalvalue := string(body_byte)
	finalvalue = finalvalue + "</p>"

	editedval := bytes.NewReader([]byte(finalvalue))
	doc, err := goquery.NewDocumentFromReader(editedval)
	linkval, _ := doc.Find("a").Attr("href")
	//fmt.Println("Link from response : " + linkval)
	actualURL, _ := url.Parse(apiURL)
	actualURL.Path = linkval
	CrawlavcaesorresultforAV(actualURL.String(), AvCaesorAVEngineResult)
	CrawlavcaesorresultTables(actualURL.String(), AvCaesorAVFileInfoResult)
	Prepareavcaesorfileinfo(AvCaesorAVFileInfoResult)
	finflag <- "finished"

}

//Prepareavcaesorfileinfo AvCaesorAVFileInfoResult for final output
func Prepareavcaesorfileinfo(AvCaesorAVFileInfoResult map[string]string) {
	for k := range AvCaesorAVFileInfoResult {

		switch strings.TrimSpace(k) {
		case "Antivirus", "Address", "Definition date", "EXE:EntryPoint", "EXE:FileFlags", "EXE:FileFlagsMask", "EXE:FileOS", "EXE:FileSubtype",
			"EXE:FileVersionNumber", "EXE:ImageVersion", "First seen", "File:FileModifyDate", "Entropy", "EXE:UninitializedDataSize",
			"EXE:PEType", "PEID BobSoft Database", "PEID Panda Database", "PEID SANS Database", "Position", "SizeOfRawData", "Url", "VirtualAddress",
			"Misc_VirtualSize", "Name", "Result", "EXE:MachineType", "EXE:Subsystem", "EXE:SubsystemVersion", "EXE:TimeStamp", "Number of RVA and Sizes",
			"Optional Header", "File:FileSize", "File:FileType", "Flags":
			delete(AvCaesorAVFileInfoResult, k)
		}

	}
}

//CrawlavcaesorresultforAV html result to prepare data for output
func CrawlavcaesorresultforAV(linkval string, AvCaesorAVEngineResult map[string]string) {
	doc, err := goquery.NewDocument(linkval)
	if err != nil {
		fmt.Println(err)
	}
	// use CSS selector found with the browser inspector
	// for each, use index and item
	doc.Find("#antivirus tr td").Each(func(index int, item *goquery.Selection) {

		propname, _ := item.Attr("class")
		if propname == "name" {
			propname = item.Text()
			if strings.Compare(strings.TrimSpace(strings.Split(item.Next().Text(), "\t")[0]), "-") != 0 &&
				strings.Compare(strings.TrimSpace(strings.Split(item.Next().Text(), "\t")[0]), "") != 0 {
				AvCaesorAVEngineResult[propname] = strings.TrimSpace(strings.Split(item.Next().Text(), "\t")[0])
			}
		}
	})
}

//CrawlavcaesorresultTables  html results for final output
func CrawlavcaesorresultTables(linkval string, AvCaesorAVFileInfoResult map[string]string) {

	doc, err := goquery.NewDocument(linkval)
	if err != nil {
		fmt.Println(err)
	}
	// use CSS selector found with the browser inspector
	// for each, use index and item
	doc.Find("table tr th").Each(func(index int, item *goquery.Selection) {
		key := item.Text()
		val := item.Next().Text()
		if strings.Compare(strings.TrimSpace(key), "PEID SysReveal Database") == 0 {
			AvCaesorAVFileInfoResult["Compiler"] = strings.TrimSpace(val)
		} else {
			AvCaesorAVFileInfoResult[key] = strings.TrimSpace(val)
		}

	})
}
