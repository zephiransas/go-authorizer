package token

import (
	"encoding/json"
	"github.com/kelseyhightower/envconfig"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type config struct {
	Url      string
	Username string
	Password string
}

func Introspection(token string) (bool, error) {
	client := &http.Client{}

	req, _ := createRequest(token)
	res, err := client.Do(req)

	if err != nil {
		return false, err
	}

	t, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return false, err
	}

	log.Println(string(t))

	r, err := parseResponse(t)
	if err != nil {
		return false, err
	}
	return r, nil
}

func createRequest(token string) (*http.Request, error) {
	values := url.Values{}
	values.Add("token", token)
	values.Add("token_type_hint", "access_token")

	cfg, err := getConfig()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(
		"POST",
		cfg.Url,
		strings.NewReader(values.Encode()))

	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(cfg.Username, cfg.Password)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req, nil
}

func getConfig() (*config, error) {
	var cfg config
	err := envconfig.Process("", &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func parseResponse(b []byte) (bool, error) {
	var res response
	err := json.Unmarshal(b, &res)
	if err != nil {
		return false, err
	}
	return res.Active, nil
}

type response struct {
	Active bool `json:"active"`
}
