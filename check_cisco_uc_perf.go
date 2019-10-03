//usr/bin/env go run "$0" "$@"; exit "$?"

// 	file: check_cisco_uc_perf.go
// 	Version 0.4.0 (01.10.2019)
//
// check_cisco_uc_perf is a Nagios plugin made by Herwig Grimm (herwig.grimm at aon.at)
// to monitor the performance Cisco Unified Communications Servers.
//
// updated by Jeremy Worden (jeremy.worden at automate.builders)
//
// I have used the Google Go programming language because of no need to install
// any libraries.
//
// The plugin uses the Cisco PerfmonPort SOAP Service via HTTPS to do a wide variety of checks.
//
// This nagios plugin is free software, and comes with ABSOLUTELY NO WARRANTY.
// It may be used, redistributed and/or modified under the terms of the GNU
// General Public Licence (see http://www.fsf.org/licensing/licenses/gpl.txt).
//
// log files and cache file:
//  		before first use create the following log files and cache file
//  		touch /var/log/check_cisco_uc_perf.log
//  		chown nagios.nagios /var/log/check_cisco_uc_perf.log
// 			for use with librenms use: chown librenms.librenms /var/log/check_cisco_uc_perf.log
//
//  		mkdir /tmp/check_cisco_uc_perf_cache
//  		chown nagios.nagios  /tmp/check_cisco_uc_perf_cache
// 			for use with librenms use: chown librenms.librenms /tmp/check_cisco_uc_perf_cache
//
//
// tested with:
// 			Cisco Unified Communications Manager CUCM version 8.6.2.22900-9
//			Cisco Unified Communications Manager CUCM version 9.1.2.11900-12
//			Cisco Unified Communications Manager CUCM version 11.0.1.20000-2
//          Cisco Unified Communications Manager CUCM version 12.0.1.23900-9
//
// see also:
// 		Cisco Unified Communications Manager XML Developers Guide, Release 9.0(1)
// 		http://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/devguide/9_0_1/xmldev-901.html
//
// changelog:
//		Version 0.1 (15.05.2014) initial release
//		Version 0.2 (20.05.2014) object caching added. new func loadStruct and saveStruct
//		Version 0.3 (27.02.2015) General Public Licence added
//		Version 0.3.1 (27.02.2015) new flag -m maximum cache age in seconds and flag -a and flag -A Cisco AXL API version of AXL XML Namespace
//		Version 0.3.2 (27.02.2015) changed flag -H usage description
//		Version 0.3.3 (30.11.2015) CUCM version 11.0: in TLSClientConfig MaxVersion set to tls.VersionTLS11 (TLS 1.1)
//		Version 0.4.0 (01.10.2019) CUCM version 12.0
//
//
// example
//		go run check_cisco_uc_perf.go  -H 10.10.10.1 -N '10.10.10.1 10.10.10.2 10.10.10.3' -u administrator -p changeMe! -o 'Cisco SIP' -A '12.0'

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	outputPrefix = "UC Perfmon"
	version      = "0.4.0"
	tmpSubdir    = "/check_cisco_uc_perf_cache/check_cisco_uc_perf_"
)

type (
	// PerfmonListCounter ...
	PerfmonListCounter struct {
		XMLName struct{} `xml:"soap:perfmonListCounter"`
		Host    string   `xml:"soap:Host"`
	}

	// PerfmonCollectCounterData ...
	PerfmonCollectCounterData struct {
		XMLName struct{} `xml:"soap:perfmonCollectCounterData"`
		Host    string   `xml:"soap:Host"`
		Object  string   `xml:"soap:Object"`
	}

	// Item ...
	Item struct {
		XMLName xml.Name `xml:"item"`
		Name    string
		Value   string
		CStatus string
	}
	// PerfmonCollectCounterDataResponse ...
	PerfmonCollectCounterDataResponse struct {
		XMLName xml.Name `xml:"perfmonCollectCounterDataResponse"`
		Item    []Item   `xml:"ArrayOfCounterInfo>item"`
	}
	// SoapBody ...
	SoapBody struct {
		XMLName                   xml.Name `xml:"Body"`
		PerfmonCollectCounterData *PerfmonCollectCounterDataResponse
	}
	// Envelope ...
	Envelope struct {
		XMLName xml.Name `xml:"Envelope"`
		Soap    *SoapBody
	}
	// ListCounterItem ...
	ListCounterItem struct {
		XMLName xml.Name `xml:"item"`
		Name    string
	}
	// ListCounterObjectItem ...
	ListCounterObjectItem struct {
		XMLName       xml.Name `xml:"item"`
		Name          string
		MultiInstance string
		Item          []ListCounterItem `xml:"ArrayOfCounter>item"`
	}
	// PerfmonListCounterResponse ...
	PerfmonListCounterResponse struct {
		XMLName xml.Name                `xml:"perfmonListCounterResponse"`
		Item    []ListCounterObjectItem `xml:"ArrayOfObjectInfo>item"`
	}
	// ListCounterSoapBody ....
	ListCounterSoapBody struct {
		XMLName                xml.Name `xml:"Body"`
		PerfmonListCounterData *PerfmonListCounterResponse
	}
	// ListCounterEnvelope ...
	ListCounterEnvelope struct {
		XMLName xml.Name `xml:"Envelope"`
		Soap    *ListCounterSoapBody
	}
)

var (
	ipAddr            string
	nodeIPAddr        string
	username          string
	password          string
	objectInstance    string
	counterName       string
	debug             int
	warningThreshold  string
	criticalThreshold string
	thresholdMinFlag  string
	showVersion       bool
	showCounters      bool
	maxCacheAge       int64
	apiVersion        string
	combinedValue     float64
)

func debugPrintf(level int, format string, a ...interface{}) {

	if level == 1 || level <= debug {
		log.Printf(format, a...)
	}
}

func isFullQualified(counterName string) bool {
	r, err := regexp.Compile(`^\\\\.*\\.*\\.*`)
	if err != nil {
		debugPrintf(1, "regexp compile error: %s\n", err)
		os.Exit(3)
	}
	if r.MatchString(counterName) {
		return true
	}

	return false
}

// save struct to json file in tmp dir
func saveStruct(ipAddr, object string, o *Envelope) bool {

	itemJSON, err := json.Marshal(o)
	if err != nil {
		debugPrintf(1, "error: %s", err)
		return false
	}

	filename := fmt.Sprintf("%s%s%d_%s_%s", os.TempDir(), tmpSubdir, os.Getuid(), ipAddr, object)

	err = ioutil.WriteFile(filename, itemJSON, 0666)

	if err != nil {
		debugPrintf(1, "error: %s", err)
		return false
	}

	return true
}

// load struct from json file in tmp dir if newer than defined in ageInSeconds
func loadStruct(ipAddr, object string, ageInSeconds int64, o *Envelope) bool {

	filename := fmt.Sprintf("%s%s%d_%s_%s", os.TempDir(), tmpSubdir, os.Getuid(), ipAddr, object)

	fs, err := os.Stat(filename)
	if err != nil {
		// debugPrintf(1, "error 1: %s", err)
		return false
	}

	debugPrintf(3, "Filename: %s Diff: %d\n", filename, time.Now().Unix()-fs.ModTime().Unix())
	if (time.Now().Unix() - fs.ModTime().Unix()) > ageInSeconds {
		return false
	}

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		debugPrintf(1, "error: %s", err)
		return false
	}
	err = json.Unmarshal(data, &o)
	if err != nil {
		debugPrintf(1, "error: %s", err)
		return false
	}
	return true
}

// Determine plugin return codes based threshold ranges
// according to "Nagios Plugin Development Guidelines"
// section "Plugin Return Codes, Threshold and ranges"
// see https://nagios-plugins.org/doc/guidelines.html
func getNagiosReturnVal(value float64, warningThresholdRange, criticalThresholdRange string, thresholdMinFlag string) int {
	r := 0
	if generateAlert(value, warningThresholdRange, thresholdMinFlag) {
		r = 1 // warning
	}
	if generateAlert(value, criticalThresholdRange, thresholdMinFlag) {
		r = 2 // critical
	}
	return r
}

// Match value against threshold range
// according to "Nagios Plugin Development Guidelines"
// section "Plugin Return Codes, Threshold and ranges"
// see https://nagios-plugins.org/doc/guidelines.html
func generateAlert(value float64, thresholdRange string, thresholdMinFlag string) bool {
	r := strings.Split(thresholdRange, ":")
	matched, _ := regexp.MatchString(`^[0-9.]+:[0-9.]+`, thresholdRange)
	switch {
	case len(r) == 1:
		float64Threshold, _ := strconv.ParseFloat(thresholdRange, 64)
		if thresholdMinFlag == "max" {
			return value < 0 || value > float64Threshold
		}
		if thresholdMinFlag == "min" {
			return value < 0 || value < float64Threshold
		}
	case strings.HasSuffix(thresholdRange, ":"):
		float64Threshold, _ := strconv.ParseFloat(r[0], 64)
		if thresholdMinFlag == "max" {
			return value < float64Threshold
		}
		if thresholdMinFlag == "min" {
			return value > float64Threshold
		}
	case strings.HasPrefix(thresholdRange, "~"):
		float64Threshold, _ := strconv.ParseFloat(r[1], 64)
		if thresholdMinFlag == "max" {
			return value > float64Threshold
		}
		if thresholdMinFlag == "min" {
			return value < float64Threshold
		}
	case matched:
		float64Threshold1, _ := strconv.ParseFloat(r[0], 64)
		float64Threshold2, _ := strconv.ParseFloat(r[1], 64)
		if thresholdMinFlag == "max" {
			return value < float64Threshold1 || value > float64Threshold2
		}
		if thresholdMinFlag == "min" {
			return value > float64Threshold1 || value < float64Threshold2
		}
	case strings.HasPrefix(thresholdRange, "@"):
		float64Threshold1, _ := strconv.ParseFloat(strings.TrimPrefix(r[0], "@"), 64)
		float64Threshold2, _ := strconv.ParseFloat(r[1], 64)
		if thresholdMinFlag == "max" {
			return value >= float64Threshold1 && value <= float64Threshold2
		}
		if thresholdMinFlag == "min" {
			return value <= float64Threshold1 && value >= float64Threshold2
		}
	}
	return true
}

func returnValText(returnVal int) string {
	statusStr := ""
	switch returnVal {
	case 0:
		statusStr = "OK"
	case 1:
		statusStr = "WARNING"
	case 2:
		statusStr = "CRITICAL"
	case 3:
		statusStr = "UNKNOWN"
	default:
		statusStr = ""
	}
	return statusStr
}

func init() {
	flag.StringVar(&ipAddr, "H", "", "AXL server IP address")
	flag.StringVar(&nodeIPAddr, "N", "", "Node IP address")
	flag.StringVar(&username, "u", "", "username")
	flag.StringVar(&password, "p", "", "password")
	flag.StringVar(&objectInstance, "o", "Cisco SIP", "Perfmon object with optional tailing instance names in parenthesis")
	flag.StringVar(&counterName, "n", "", "Counter name")
	flag.IntVar(&debug, "d", 3, "print debug, level: 1 errors only, 2 warnings and 3 informational messages")
	flag.StringVar(&warningThreshold, "w", "0", "Warning threshold or threshold range")
	flag.StringVar(&criticalThreshold, "c", "0", "Critical threshold or threshold range")
	flag.StringVar(&thresholdMinFlag, "f", "max", "use thresold as min value rather than max")
	flag.BoolVar(&showVersion, "V", false, "print plugin version")
	flag.BoolVar(&showCounters, "l", false, "print PerfmonListCounter")
	flag.Int64Var(&maxCacheAge, "m", 180, "maximum cache age in seconds")
	flag.StringVar(&apiVersion, "A", "12.0", "Cisco AXL API version of AXL XML Namespace")
}

func main() {

	logfile, err := os.OpenFile("/var/log/check_cisco_uc_perf.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		debugPrintf(2, "Can't open log file\n")
		os.Exit(3)
	}

	defer logfile.Close()

	flag.Parse()
	returnVal := 3
	fullCounterName := ""
	usePersistData := false

	if showVersion {
		fmt.Printf("%s version: %s\n", path.Base(os.Args[0]), version)
		os.Exit(0)
	}

	// log.SetOutput(os.Stdout)

	log.SetOutput(logfile)

	// remove tailing instance names and parenthesis
	object := ""
	if pos := strings.Index(objectInstance, "("); pos != -1 {
		object = objectInstance[:pos]
	} else {
		object = objectInstance
	}

	debugPrintf(3, "CUCM IP address: %s Node IP address: %s\n", ipAddr, nodeIPAddr)
	debugPrintf(3, "Perfmon object: %s Counter name: %s\n", object, counterName)
	debugPrintf(3, "Counter instance name: %s max cache age: %d\n", objectInstance, maxCacheAge)

	nodeIPAddrArr := strings.Split(nodeIPAddr, " ")
	debugPrintf(3, "Node array: %s", nodeIPAddrArr)

	for _, s := range nodeIPAddrArr {
		envelope := new(Envelope)
		loaded := loadStruct(s, object, maxCacheAge, envelope)
		if !loaded {
			debugPrintf(3, "No persistence file found or persistence file too old\n")
			usePersistData = false
		} else {
			debugPrintf(3, "Persistence file found: %+v\n", envelope)
			if isFullQualified(counterName) {
				fullCounterName = counterName
			} else {
				fullCounterName = fmt.Sprintf("\\\\%s\\%s\\%s", s, object, counterName)
			}
			for _, v := range envelope.Soap.PerfmonCollectCounterData.Item {
				if v.Name == fullCounterName {
					debugPrintf(3, "Name: %s Value: %s\n", v.Name, v.Value)
				}
			}
			usePersistData = true
		}

		debugPrintf(3, "use persistence: %v\n", usePersistData)

		if !usePersistData || showCounters {

			client := &http.Client{

				Transport: &http.Transport{
					Proxy: http.ProxyFromEnvironment,
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
						MaxVersion:         tls.VersionTLS11,
					},
				},
			}

			xmlHeader := []byte(`<?xml version="1.0" encoding="utf-8" ?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.cisco.com/ast/soap"><soapenv:Header/><soapenv:Body>`)
			xmlFooter := []byte(`</soapenv:Body></soapenv:Envelope>`)

			xmlData := make([]byte, 32768)

			if showCounters {
				reqData := &PerfmonListCounter{Host: s}
				xmlData, _ = xml.Marshal(reqData)
			} else {
				reqData := &PerfmonCollectCounterData{Host: s, Object: object}
				xmlData, _ = xml.Marshal(reqData)
			}

			bufAll := make([]byte, 32768)

			bufAll = append(bufAll, xmlHeader...)
			bufAll = append(bufAll, xmlData...)
			bufAll = append(bufAll, xmlFooter...)

			xmlAll := fmt.Sprintf("%s%s%s", xmlHeader, xmlData, xmlFooter)

			debugPrintf(4, "XMP SOAP request: %s\n", xmlAll)

			data := bytes.NewBufferString(xmlAll)

			url := "https://" + ipAddr + ":8443/perfmonservice/services/PerfmonPort"
			debugPrintf(3, "URL: %s\n", url)
			req, err := http.NewRequest("POST", url, data)
			req.Header.Add("Content-type", "text/xml")
			req.Header.Add("SOAPAction", "CUCM:DB ver="+apiVersion)
			req.SetBasicAuth(username, password)

			debugPrintf(4, "username: %s, password: %s\n", username, password)

			resp, err := client.Do(req)
			if err != nil {
				debugPrintf(1, "HTTPS request error: %s %#v\n", err, resp)
				os.Exit(3)
			}
			defer resp.Body.Close()
			body, _ := ioutil.ReadAll(resp.Body)

			debugPrintf(4, "XMP SOAP response: %s\n", body)

			if showCounters {
				envelope := new(ListCounterEnvelope)
				err = xml.Unmarshal([]byte(body), envelope)
				if err != nil {
					debugPrintf(1, "ListCounterEnvelope XML unmarshal error: %s\n", err)
					os.Exit(3)
				}

				fmt.Printf("%d items\n", len(envelope.Soap.PerfmonListCounterData.Item))

				for _, v := range envelope.Soap.PerfmonListCounterData.Item {
					fmt.Printf("%v\n", v.Name)
					for _, c := range v.Item {
						fmt.Printf("\t%s\n", c.Name)
					}
				}
				os.Exit(0)
			}

			// envelope := new(Envelope)
			err = xml.Unmarshal([]byte(body), envelope)
			if err != nil {
				debugPrintf(1, "XML unmarshal error: %s\n", err)
				os.Exit(3)
			}
			saveStruct(s, object, envelope)
		}

		if len(counterName) > 0 {
			if isFullQualified(counterName) {
				fullCounterName = counterName
			} else {
				fullCounterName = fmt.Sprintf("\\\\%s\\%s\\%s", s, objectInstance, counterName)
			}
			debugPrintf(3, "fullCounterName: >>%s<<\n", fullCounterName)
			for _, v := range envelope.Soap.PerfmonCollectCounterData.Item {
				if v.Name == fullCounterName {
					// fmt.Printf("%s\n", v.Value)
					value, err := strconv.ParseFloat(v.Value, 64)
					if err != nil {
						debugPrintf(1, "Counter value string to float64 convert error: %s\n", err)
					} else {
						combinedValue += value
					}
				}
			}
		} else {
			// find longest Name
			maxLen := 0
			for _, v := range envelope.Soap.PerfmonCollectCounterData.Item {
				if l := len(v.Name); l > maxLen {
					maxLen = l
				}
			}

			for _, v := range envelope.Soap.PerfmonCollectCounterData.Item {
				space := strings.Repeat(" ", maxLen+3-len(v.Name))
				fmt.Printf("Name: %s%sValue: %s\n", v.Name, space, v.Value)

			}

		}
	}

	returnVal = getNagiosReturnVal(combinedValue, warningThreshold, criticalThreshold, thresholdMinFlag)
	debugPrintf(3, "returnVal: %d\n", returnVal)
	statusStr := returnValText(returnVal)

	nagiosOutput := fmt.Sprintf("%s - %s,%s,%s=%s|%s=%s;%s;%s;;", statusStr, outputPrefix, objectInstance, counterName, fmt.Sprintf("%.0f", combinedValue), counterName, fmt.Sprintf("%.0f", combinedValue), warningThreshold, criticalThreshold)
	nagiosOutput = html.EscapeString(nagiosOutput)
	nagiosOutput = strings.Replace(nagiosOutput, "%", "Percent", -1)
	nagiosOutput = strings.Replace(nagiosOutput, "\\", "\\\\", -1)
	fmt.Printf("%s\n", nagiosOutput)
	os.Exit(returnVal)

}
