/*

The following code is a proof of concept:
Project Title: haveIbeenpwned
Goal or Aim:
 * As a Proof Of Concept to run against online API "have I been pwned" in order to find compromised email addresses, and which data breaches they may have been part of.
ToDo:
 -

 
  written by Haptik Drift
  <haptikdrift@gmail.com>
*/

package main

/* All imports needed in the main function */
import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

/* Global vars initiated here. On Linux store this key as an environment variable, example: $ export HIBP_KEY="<my_HIBP_API_key>"*/
var key = os.Args[1]

/*	########################################################################################################	*/
/*
	###
	# Start MAIN Function
	###
*/

/*
basic useage example;
$ go run ./haveIbeenPwnd.go $HIBP_KEY enum-emails.txt
*/
func main() {
	// grab emails from file
	emails, _ := FileToSlice(os.Args[2])
	var breach = []Breach{}
	_ = json.Unmarshal(BreachFetch(), &breach)
	for _, email := range emails {
		becheck := []BECheck{}
		_ = json.Unmarshal(BreachEmailCheck(email), &becheck)
		for _, ename := range becheck {
			for _, bname := range breach {
				if ename.Name == bname.Name {
					// The below will print output to screen in an html table block, remove the block and rewrite as clear text if needed
					fmt.Printf(`
<p><br />The following email <b><i>%s</i></b> was compromised in the following breach shown in the table below; </p>
<table style="border-collapse: collapse; width: 99.9819%%;" border="1">
<tbody>
<tr><td style="width: 9.2%%;">Name</td><td style="width: 90.8%%;">%s -&nbsp; %s&nbsp;</td></tr>
<tr><td style="width: 9.2%%;">Description</td><td style="width: 90.8%%;">%s&nbsp;</td></tr>
<tr><td style="width: 9.2%%;">Data Lost</td><td style="width: 90.8%%;">%s</td></tr>
</tbody>
</table>
`, email, bname.Name, email, bname.Description, bname.DataClasses)
				}
			}
		}
		// Once the initial call is made for 1 email address, a wait timer is added to comply with "have I been pwned" API rate limiting
		time.Sleep(3 * time.Second)
	}
}

/*
	###
	# End MAIN Function
	###
*/
/*	########################################################################################################	*/

/*	########################################################################################################	*/
/*
	###
	# Functions used inside the main loop
	###
*/

/* Func for collecting breach data held on "have I been pwned". Typically now key is needed by the API to run this function but has been added here for code efficiency. */
func BreachFetch() []byte {
	url := "https://haveibeenpwned.com/api/v3/breaches"
	method := "GET"

	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		fmt.Println(err)
	}
	req.Header.Add("Hibp-Api-Key", key)

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
	}
	return body
}

/* This will querry an email address provided. The "have I been pwned" API has a rate limit, which has not been implemented here, please see main() func */
func BreachEmailCheck(s string) []byte {
	url := fmt.Sprintf(`https://haveibeenpwned.com/api/v3/breachedaccount/%s`, s)
	method := "GET"

	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		fmt.Println(err)
	}
	req.Header.Add("Hibp-Api-Key", key)

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
	}
	return body
}

/* This will create a slice from a file*/
func FileToSlice(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []string
	scan := bufio.NewScanner(file)
	for scan.Scan() {
		lines = append(lines, scan.Text())
	}
	return lines, scan.Err()
}

/* When an email is checked a JSON respose is returned */
type BECheck struct {
	Name string `json:"Name"`
}

/* This stuct is for the Breach data reurned to held and stored for the duration on the application/script run time */
type Breach struct {
	Name         string    `json:"Name"`
	Title        string    `json:"Title"`
	Domain       string    `json:"Domain"`
	BreachDate   string    `json:"BreachDate"`
	AddedDate    time.Time `json:"AddedDate"`
	ModifiedDate time.Time `json:"ModifiedDate"`
	PwnCount     int       `json:"PwnCount"`
	Description  string    `json:"Description"`
	LogoPath     string    `json:"LogoPath"`
	DataClasses  []string  `json:"DataClasses"`
	IsVerified   bool      `json:"IsVerified"`
	IsFabricated bool      `json:"IsFabricated"`
	IsSensitive  bool      `json:"IsSensitive"`
	IsRetired    bool      `json:"IsRetired"`
	IsSpamList   bool      `json:"IsSpamList"`
	IsMalware    bool      `json:"IsMalware"`
}
