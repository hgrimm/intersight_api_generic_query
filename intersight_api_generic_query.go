// 	file: intersight_api_generic_query.go
// 	Version 0.1 (07.10.2021)
//

// The intersight_api_generic_query CLI command can be used to query, add,
// update, // and delete configuration and alarm data on Cisco UCS Rack, Blade,
// Nexus, and Hyperflex cluster hardware.
// Herwig Grimm (herwig.grimm at gmail.at)
// Intersight API reference: https://intersight.com/apidocs/apirefs/

// Examples:

package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-fed/httpsig"
)

var (
	privateKeyFile     string
	publicKeyId        string
	endpointAuthority  string
	endpointPath       string
	endpointQuery      string
	httpMethod         string
	httpBody           string
	jsonQueryStr       string
	debug              int
	expectString       string
	zeroInst           bool
	faultsOnly         bool
	warningThreshold   string
	criticalThreshold  string
	proxyURL           string
	insecureSkipVerify bool
)

func init() {
	flag.StringVar(&privateKeyFile, "K", "", "path and filename of private key file")
	flag.StringVar(&publicKeyId, "i", "", "public key ID")

	flag.StringVar(&endpointAuthority, "A", "", "API endpoint URL authority = [userinfo \"@\"] host [\":\" port]")
	flag.StringVar(&endpointPath, "p", "", "API endpoint URL path")
	flag.StringVar(&endpointQuery, "q", "", "API endpoint URL query")

	flag.StringVar(&expectString, "E", "", "expect string as a regular expression")
	flag.StringVar(&jsonQueryStr, "Q", ".Results[]", "JSON query string. Here you can find details: https://stedolan.github.io/jq/manual/")
	flag.StringVar(&httpMethod, "m", "", "HTTP method (GET, POST, ...)")
	flag.StringVar(&httpBody, "b", "", "HTTP body or payload")
	flag.IntVar(&debug, "d", 0, "print debug, level: 0 no messages (default), 1 errors only, 2 warnings and 3 informational messages")
	flag.BoolVar(&zeroInst, "z", false, "true or false. if set to true the check will return OK status if zero instances where found. Default is false.")
	flag.BoolVar(&faultsOnly, "F", false, "display only faults in output")
	flag.StringVar(&warningThreshold, "w", "1", "Warning threshold or threshold range")
	flag.StringVar(&criticalThreshold, "c", "1", "Critical threshold or threshold range")
	flag.StringVar(&proxyURL, "P", "", "proxy URL. Format: http://<user>:<password>@<ip_addr>:<port>")
	flag.BoolVar(&insecureSkipVerify, "k", false, "controls whether a client verifies the server's certificate chain and host name.")
}

// Determine plugin return codes based threshold ranges
// according to "Nagios Plugin Development Guidelines"
// section "Plugin Return Codes, Threshold and ranges"
// see https://nagios-plugins.org/doc/guidelines.html
func getNagiosReturnVal(value float64, warningThresholdRange, criticalThresholdRange string) int {
	r := 0
	if generateAlert(value, warningThresholdRange) {
		r = 1 // warning
	}
	if generateAlert(value, criticalThresholdRange) {
		r = 2 // critical
	}
	return r
}

// Match value against threshold range
// according to "Nagios Plugin Development Guidelines"
// section "Plugin Return Codes, Threshold and ranges"
// see https://nagios-plugins.org/doc/guidelines.html
func generateAlert(value float64, thresholdRange string) bool {
	r := strings.Split(thresholdRange, ":")
	matched, _ := regexp.MatchString(`^[0-9.]+:[0-9.]+`, thresholdRange)
	switch {
	case len(r) == 1:
		float64_threshold, _ := strconv.ParseFloat(thresholdRange, 64)
		return value < 0 || value > float64_threshold
	case strings.HasSuffix(thresholdRange, ":"):
		float64_threshold, _ := strconv.ParseFloat(r[0], 64)
		return value < float64_threshold
	case strings.HasPrefix(thresholdRange, "~"):
		float64_threshold, _ := strconv.ParseFloat(r[1], 64)
		return value > float64_threshold
	case matched:
		float64_threshold1, _ := strconv.ParseFloat(r[0], 64)
		float64_threshold2, _ := strconv.ParseFloat(r[1], 64)
		return value < float64_threshold1 || value > float64_threshold2
	case strings.HasPrefix(thresholdRange, "@"):
		float64_threshold1, _ := strconv.ParseFloat(strings.TrimPrefix(r[0], "@"), 64)
		float64_threshold2, _ := strconv.ParseFloat(r[1], 64)
		return value >= float64_threshold1 && value <= float64_threshold2
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

func debugPrintf(level int, format string, a ...interface{}) {
	if level <= debug {
		log.Printf(format, a...)
	}
}

func main() {

	flag.Parse()

	endpointQueryItems := strings.Split(endpointQuery, "&")

	APIURL := &url.URL{
		Scheme: "https",
		Host:   endpointAuthority,
		Path:   endpointPath,
	}
	queryValues := url.Values{}
	for _, item := range endpointQueryItems {
		itemParts := strings.SplitN(item, "=", 2)
		if len(itemParts) > 1 {
			queryValues.Add(itemParts[0], itemParts[1])
		}
	}

	APIURL.RawQuery = queryValues.Encode()
	debugPrintf(3, "APIURL.RawQuery %#v\n", APIURL.RawQuery)
	endpoint := fmt.Sprintf("%s", APIURL)
	debugPrintf(3, "endpoint: %s\n", endpoint)
	debugPrintf(3, "HTTP method: %s\n", httpMethod)
	debugPrintf(3, "jsonQueryStr: %s\n", jsonQueryStr)

	client := &http.Client{}
	if len(proxyURL) > 0 {
		parsedURL, err := url.Parse(proxyURL)
		if err != nil {
			log.Printf("error during proxy URL parsing: %s", err)
		}
		client = &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(parsedURL),
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: insecureSkipVerify,
				},
			},
		}
	} else {
		client = &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: insecureSkipVerify,
				},
			},
		}
	}

	privateKey, err := loadPrivateKey(privateKeyFile)
	if err != nil {
		log.Printf("error loading private key: %s", err)
	}

	body := []byte(httpBody)
	var r *http.Request
	if httpMethod == "POST" {
		r, err = http.NewRequest(httpMethod, endpoint, bytes.NewBuffer(body))
	}

	if httpMethod == "GET" {
		r, err = http.NewRequest(httpMethod, endpoint, nil)
	}

	if err != nil {
		log.Printf("error creating request: %s", err)
		os.Exit(3)
	}

	endpointUrlParts, err := url.Parse(endpoint)
	if err != nil {
		log.Printf("error during URL parsing: %s", err)
	}

	debugPrintf(2, "endpointUrlParts: %#v\n", endpointUrlParts)
	requestTarget := fmt.Sprintf("%s %s", strings.ToLower(httpMethod), strings.ToLower(endpointUrlParts.Path))
	debugPrintf(2, "requestTarget: %#v\n", requestTarget)

	r.Header["(request-target)"] = []string{requestTarget}
	datetime := time.Now().UTC()
	dateStr := datetime.Format(time.RFC1123)
	r.Header["Date"] = []string{dateStr}
	setDigest(r)
	r.Header["Host"] = []string{r.URL.Host}

	headers := []string{"(request-target)", "date", "digest", "host"}

	s, _, err := httpsig.NewSigner([]httpsig.Algorithm{httpsig.RSA_SHA256}, httpsig.DigestSha256, headers, httpsig.Authorization, 0)
	if err != nil {
		log.Printf("error creating signer: %s", err)
		os.Exit(3)
	}

	if err := s.SignRequest(privateKey, publicKeyId, r, nil); err != nil {
		log.Printf("error signing request: %s", err)
		os.Exit(3)
	}

	r.Header["Accept"] = []string{"application/json"}
	r.Header["Content-Type"] = []string{"application/json"}
	r.Header.Del("(request-target)")
	debugPrintf(3, "Request headers: %v\n", r.Header)

	resp, err := client.Do(r)
	if err != nil {
		fmt.Println("Errored when sending request to the server")
		return
	}

	defer resp.Body.Close()
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	debugPrintf(1, "Reponse status code: %v\n", resp.Status)
	debugPrintf(3, "Reponse body: %v\n\n", string(responseBody))

	/* 	jsonQuery, err := gojq.Parse(jsonQueryStr)
	   	if err != nil {
	   		log.Fatal(err)
	   	}

	   	var parsedJSON map[string]interface{}
	   	json.Unmarshal(responseBody, &parsedJSON)

	   	iter := jsonQuery.Run(parsedJSON)
	   	for {
	   		v, ok := iter.Next()
	   		if !ok {
	   			break
	   		}
	   		fmt.Printf("%s", v)
	   	} */

	fmt.Println(string(responseBody))

}

func setDigest(r *http.Request) ([]byte, error) {
	var bodyBytes []byte
	if _, ok := r.Header["Digest"]; !ok {
		body := ""
		if r.Body != nil {
			var err error
			bodyBytes, err = ioutil.ReadAll(r.Body)
			if err != nil {
				return nil, fmt.Errorf("error reading body. %v", err)
			}

			// And now set a new body, which will simulate the same data we read:
			r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
			body = string(bodyBytes)
		}

		d := sha256.Sum256([]byte(body))
		r.Header["Digest"] = []string{fmt.Sprintf("SHA-256=%s", base64.StdEncoding.EncodeToString(d[:]))}
	}

	return bodyBytes, nil
}

func loadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	keyData, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Print(err)
	}

	pem, _ := pem.Decode(keyData)
	if pem.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("RSA private key is of the wrong type: %s", pem.Type)
	}

	return x509.ParsePKCS1PrivateKey(pem.Bytes)
}

func loadPrivateKeyOld(keyData []byte) (*rsa.PrivateKey, error) {
	pem, _ := pem.Decode(keyData)
	if pem.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("RSA private key is of the wrong type: %s", pem.Type)
	}

	return x509.ParsePKCS1PrivateKey(pem.Bytes)
}
