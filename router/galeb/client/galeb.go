// Copyright 2014 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/tsuru/tsuru/log"
	"github.com/tsuru/tsuru/net"
	"strconv"
)

type ErrItemNotFound struct {
	path string
}

func (e ErrItemNotFound) Error() string {
	return fmt.Sprintf("item not found: %s", e.path)
}

type ErrItemAlreadyExists struct {
	path   string
	params interface{}
}

func (e ErrItemAlreadyExists) Error() string {
	return fmt.Sprintf("item already exists: %s - %#v", e.path, e.params)
}

type ErrAmbiguousSearch struct {
	path  string
	items []commonPostResponse
}

func (e ErrAmbiguousSearch) Error() string {
	return fmt.Sprintf("more than one item returned in search: %s - %#v", e.path, e.items)
}

type GalebClient struct {
	ApiUrl        string
	Username      string
	Password      string
	Token         string
	TokenHeader   string
	Environment   string
	Project       string
	BalancePolicy string
	RuleType      string
	WaitTimeout   time.Duration
	Debug         bool
}

func (c *GalebClient) doRequest(method, path string, params interface{}) (*http.Response, error) {
	buf := bytes.Buffer{}
	contentType := "application/json"
	if params != nil {
		switch val := params.(type) {
		case string:
			contentType = "text/uri-list"
			buf.WriteString(val)
		default:
			err := json.NewEncoder(&buf).Encode(params)
			if err != nil {
				return nil, err
			}
		}
	}
	url := fmt.Sprintf("%s/%s", strings.TrimRight(c.ApiUrl, "/"), strings.TrimLeft(path, "/"))
	var bodyData string
	if c.Debug {
		bodyData = buf.String()
	}
	req, err := http.NewRequest(method, url, &buf)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		header := c.TokenHeader
		if header == "" {
			header = "x-auth-token"
		}
		req.Header.Set(header, c.Token)
	} else {
		req.SetBasicAuth(c.Username, c.Password)
	}
	req.Header.Set("Content-Type", contentType)
	rsp, err := net.Dial5Full60ClientNoKeepAlive.Do(req)
	if c.Debug {
		var code int
		if err == nil {
			code = rsp.StatusCode
		}
		log.Debugf("galeb %s %s %s: %d", method, url, bodyData, code)
	}
	return rsp, err
}

func (c *GalebClient) doCreateResource(path string, params interface{}) (string, error) {
	rsp, err := c.doRequest("POST", path, params)
	if err != nil {
		return "", err
	}
	if rsp.StatusCode == http.StatusConflict {
		return "", ErrItemAlreadyExists{path: path, params: params}
	}
	if rsp.StatusCode != http.StatusCreated {
		responseData, _ := ioutil.ReadAll(rsp.Body)
		rsp.Body.Close()
		return "", errors.Errorf("POST %s: invalid response code: %d: %s - PARAMS: %#v", path, rsp.StatusCode, string(responseData), params)
	}
	location := rsp.Header.Get("Location")
	if location == "" {
		return "", errors.Errorf("POST %s: empty location header. PARAMS: %#v", path, params)
	}
	return location, nil
}

func (c *GalebClient) fillDefaultPoolValues(params *Pool) {
	if params.Environment == "" {
		params.Environment = c.Environment
	}
	if params.Project == "" {
		params.Project = c.Project
	}
	if params.BalancePolicy == "" {
		params.BalancePolicy = c.BalancePolicy
	}
}

func (c *GalebClient) fillDefaultRuleValues(params *Rule) {
	params.Matching = "/"
	if params.Project == "" {
		params.Project = c.Project
	}
}

func (c *GalebClient) fillDefaultRuleOrderedValues(params *RuleOrdered) {
	if params.Environment == "" {
		params.Environment = c.Environment
	}
	params.Order = "1"
}

func (c *GalebClient) fillDefaultVirtualHostValues(params *VirtualHost) {
	if len(params.Environment) == 0 {
		params.Environment = []string{c.Environment}
	}
	if params.Project == "" {
		params.Project = c.Project
	}
}

func (c *GalebClient) AddVirtualHost(addr string) (string, error) {
	var params VirtualHost
	c.fillDefaultVirtualHostValues(&params)
	params.Name = addr
	resource, err := c.doCreateResource("/virtualhost", &params)
	if err != nil {
		return "", err
	}
	return resource, c.waitStatusOK(resource)
}

func (c *GalebClient) AddVirtualHostWithGroup(addr string, virtualHostWithGroup string) (string, error) {
	virtualHostID, err := c.findItemByName("virtualhost", virtualHostWithGroup)
	if err != nil {
		return "", err
	}
	virtualhostGroupId, err := c.FindVirtualHostGroupByVirtualHostId(virtualHostID)
	if err != nil {
		return "", err
	}

	var params VirtualHost
	c.fillDefaultVirtualHostValues(&params)
	params.Name = addr
	params.VirtualHostGroup = fmt.Sprintf("%s/virtualhostgroup/%s", c.ApiUrl, virtualhostGroupId)
	resource, err := c.doCreateResource("/virtualhost", &params)
	if err != nil {
		return "", err
	}
	return resource, c.waitStatusOK(resource)
}

func (c *GalebClient) AddBackendPool(name string) (string, error) {
	var params Pool
	c.fillDefaultPoolValues(&params)
	params.Name = name
	resource, err := c.doCreateResource("/pool", &params)
	if err != nil {
		return "", err
	}
	return resource, c.waitStatusOK(resource)
}

func (c *GalebClient) UpdatePoolProperties(poolName string, properties BackendPoolHealthCheck) error {
	poolID, err := c.findItemByName("pool", poolName)
	if err != nil {
		return err
	}
	path := strings.TrimPrefix(poolID, c.ApiUrl)
	var poolParam Pool
	c.fillDefaultPoolValues(&poolParam)
	poolParam.Name = poolName
	poolParam.BackendPoolHealthCheck = properties
	rsp, err := c.doRequest("PATCH", path, poolParam)
	if err != nil {
		return err
	}
	if rsp.StatusCode != http.StatusNoContent {
		responseData, _ := ioutil.ReadAll(rsp.Body)
		rsp.Body.Close()
		return errors.Errorf("PATCH %s: invalid response code: %d: %s", path, rsp.StatusCode, string(responseData))
	}
	return c.waitStatusOK(poolID)
}

func (c *GalebClient) AddBackend(backend *url.URL, poolName string) (string, error) {
	var params Target
	params.Name = backend.String()
	poolID, err := c.findItemByName("pool", poolName)
	if err != nil {
		return "", err
	}
	params.BackendPool = poolID
	resource, err := c.doCreateResource("/target", &params)
	if err != nil {
		return "", err
	}
	return resource, c.waitStatusOK(resource)
}

func (c *GalebClient) AddBackends(backends []*url.URL, poolName string) error {
	poolID, err := c.findItemByName("pool", poolName)
	if err != nil {
		return err
	}
	errCh := make(chan error, len(backends))
	wg := sync.WaitGroup{}
	for i := range backends {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var params Target
			params.Name = backends[i].String()
			params.BackendPool = poolID
			resource, cerr := c.doCreateResource("/target", &params)
			if cerr != nil {
				if _, ok := cerr.(ErrItemAlreadyExists); ok {
					return
				}
				errCh <- cerr
			}
			cerr = c.waitStatusOK(resource)
			if cerr != nil {
				errCh <- cerr
			}
		}(i)
	}
	done := make(chan bool)
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case err = <-errCh:
		return err
	}
	return nil
}

func (c *GalebClient) AddRuleToID(name, poolID string) (string, error) {
	var params Rule
	c.fillDefaultRuleValues(&params)
	params.Name = name
	params.BackendPool = append(params.BackendPool, poolID)
	return c.doCreateResource("/rule", &params)
}

func (c *GalebClient) SetRuleVirtualHostIDs(ruleID, virtualHostID string) error {

	virtualHostGroupId, err := c.FindVirtualHostGroupByVirtualHostId(virtualHostID)

	if err != nil {
		return err
	}

	var params RuleOrdered
	c.fillDefaultRuleOrderedValues(&params)
	params.Rule = ruleID
	params.VirtualHostGroup = fmt.Sprintf("%s/virtualhostgroup/%s", c.ApiUrl, virtualHostGroupId)

	resource, err := c.doCreateResource("/ruleordered", &params)
	if err != nil {
		return err
	}

	return c.waitStatusOK(resource)
}

func (c *GalebClient) SetRuleVirtualHost(ruleName, virtualHostName string) error {
	ruleID, err := c.findItemByName("rule", ruleName)
	if err != nil {
		return err
	}
	virtualHostID, err := c.findItemByName("virtualhost", virtualHostName)
	if err != nil {
		return err
	}
	return c.SetRuleVirtualHostIDs(ruleID, virtualHostID)
}

func (c *GalebClient) RemoveBackendByID(backendID string) error {
	backend, err := c.removeResource(backendID)
	if err != nil {
		return nil
	}
	err = c.waitStatusOK(backend)
	return err
}

func (c *GalebClient) RemoveBackendsByIDs(backendIDs []string) error {
	errCh := make(chan error, len(backendIDs))
	wg := sync.WaitGroup{}
	for i := range backendIDs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			backend, err := c.removeResource(backendIDs[i])
			if err != nil {
				errCh <- err
			} else {
				err = c.waitStatusOK(backend)
			}
		}(i)
	}
	done := make(chan bool)
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case err := <-errCh:
		return err
	}
	return nil
}

func (c *GalebClient) RemoveBackendPool(poolName string) error {
	id, err := c.findItemByName("pool", poolName)
	if err != nil {
		return err
	}
	backendPool, err := c.removeResource(id)
	if err != nil {
		return err
	}
	err = c.waitStatusOK(backendPool)
	return err
}

func (c *GalebClient) RemoveVirtualHost(virtualHostName string) error {
	id, err := c.findItemByName("virtualhost", virtualHostName)
	if err != nil {
		return err
	}
	virtualHost, err := c.removeResource(id)
	if err != nil {
		return err
	}
	err = c.waitStatusOK(virtualHost)
	return err
}

func (c *GalebClient) RemoveVirtualHostByID(virtualHostID string) error {
	virtualHost, err := c.removeResource(virtualHostID)
	if err != nil {
		return err
	}
	err = c.waitStatusOK(virtualHost)
	return err
}

func (c *GalebClient) RemoveRule(ruleName string) error {
	ruleID, err := c.findItemByName("rule", ruleName)
	if err != nil {
		return err
	}
	rule, err := c.removeResource(ruleID)
	if err != nil {
		return err
	}
	err = c.waitStatusOK(rule)
	return err
}

func (c *GalebClient) FindVirtualHostGroupByVirtualHostId(virtualHostId string) (virtualHostGroupId string, err error) {

	path := fmt.Sprintf("%s/virtualhostgroup", strings.TrimPrefix(virtualHostId, c.ApiUrl))
	rsp, err := c.doRequest("GET", path, nil)

	if err != nil {
		return "", err
	}
	defer rsp.Body.Close()
	responseData, _ := ioutil.ReadAll(rsp.Body)
	if rsp.StatusCode != http.StatusOK {
		return "", errors.Errorf("GET %s/virtualhostgroup: wrong status code: %d. content: %s", strings.TrimPrefix(virtualHostId, c.ApiUrl), rsp.StatusCode, string(responseData))
	}
	var rspObj struct {
		VirtualHostGroupId int `json:"id"`
	}
	err = json.Unmarshal(responseData, &rspObj)
	if err != nil {
		return "", errors.Wrapf(err, "GET %s/virtualhostgroup: unable to parse: %s", strings.TrimPrefix(virtualHostId, c.ApiUrl), string(responseData))
	}
	return strconv.Itoa(rspObj.VirtualHostGroupId), nil
}

func (c *GalebClient) FindTargetsByParent(poolName string) ([]Target, error) {
	path := fmt.Sprintf("/target/search/findAllByPoolName?name=%s&size=999999", poolName)
	rsp, err := c.doRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()
	responseData, _ := ioutil.ReadAll(rsp.Body)
	if rsp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("GET /target/search/findAllByPoolName?name={parentName}: wrong status code: %d. content: %s", rsp.StatusCode, string(responseData))
	}
	var rspObj struct {
		Embedded struct {
			Targets []Target `json:"target"`
		} `json:"_embedded"`
	}
	err = json.Unmarshal(responseData, &rspObj)
	if err != nil {
		return nil, errors.Wrapf(err, "GET /target/search/findAllByPoolName?name={parentName}: unable to parse: %s", string(responseData))
	}
	return rspObj.Embedded.Targets, nil
}

func  (c *GalebClient) FindVirtualHostsByGroup(virtualHostName string) ([]VirtualHost, error) {
	virtualHostID, err := c.findItemByName("virtualhost", virtualHostName)
	if err != nil {
		return nil, err
	}

	virtualHostGroupId, err := c.FindVirtualHostGroupByVirtualHostId(virtualHostID)

	path := fmt.Sprintf("%s/virtualhostgroup/%s/virtualhosts", c.ApiUrl, virtualHostGroupId)
	rsp, err := c.doRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()
	responseData, _ := ioutil.ReadAll(rsp.Body)
	if rsp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("GET /virtualhostgroup/{id}/virtualhosts: wrong status code: %d. content: %s", rsp.StatusCode, string(responseData))
	}
	var rspObj struct {
		Embedded struct {
			VirtualHosts []VirtualHost `json:"virtualhost"`
		} `json:"_embedded"`
	}
	err = json.Unmarshal(responseData, &rspObj)
	if err != nil {
		return nil, errors.Wrapf(err, "GET /virtualhostgroup/{id}/virtualhosts: unable to parse: %s", string(responseData))
	}
	return rspObj.Embedded.VirtualHosts, nil


}

func (c *GalebClient) Healthcheck() error {
	rsp, err := c.doRequest("GET", "/healthcheck", nil)
	if err != nil {
		return err
	}
	defer rsp.Body.Close()
	data, _ := ioutil.ReadAll(rsp.Body)
	dataStr := string(data)
	if rsp.StatusCode != http.StatusOK {
		return errors.Errorf("wrong healthcheck status code: %d. content: %s", rsp.StatusCode, dataStr)
	}
	if !strings.HasPrefix(dataStr, "WORKING") {
		return errors.Errorf("wrong healthcheck response: %s.", dataStr)
	}
	return nil
}

func (c *GalebClient) removeResource(resourceURI string) (string, error) {
	path := strings.TrimPrefix(resourceURI, c.ApiUrl)
	rsp, err := c.doRequest("DELETE", path, nil)
	if err != nil {
		return "", err
	}
	defer rsp.Body.Close()
	responseData, _ := ioutil.ReadAll(rsp.Body)

	if rsp.StatusCode != http.StatusNoContent {
		return "", errors.Errorf("DELETE %s: invalid response code: %d: %s", path, rsp.StatusCode, string(responseData))
	}
	return path, nil
}

func (c *GalebClient) findItemByName(item, name string) (string, error) {
	path := fmt.Sprintf("/%s/search/findByName?name=%s", item, name)
	rsp, err := c.doRequest("GET", path, nil)
	if err != nil {
		return "", err
	}
	var rspObj struct {
		Embedded map[string][]commonPostResponse `json:"_embedded"`
	}
	defer rsp.Body.Close()
	rspData, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(rspData, &rspObj)
	if err != nil {
		return "", errors.Wrapf(err, "unable to parse find response %q", string(rspData))
	}
	itemList := rspObj.Embedded[item]
	if len(itemList) == 0 {
		return "", ErrItemNotFound{path: path}
	}
	if len(itemList) > 1 {
		return "", ErrAmbiguousSearch{path: path, items: itemList}
	}
	id := rspObj.Embedded[item][0].FullId()
	if id == "" {
		return "", ErrItemNotFound{path: path}
	}
	return id, nil
}

func (c *GalebClient) fetchPathStatus(path string) (map[string]string, int, error) {
	rsp, err := c.doRequest("GET", path, nil)
	if err != nil {
		return nil, -1, errors.Wrapf(err, "GET %s: unable to make request", path)
	}
	defer rsp.Body.Close()
	responseData, _ := ioutil.ReadAll(rsp.Body)
	if rsp.StatusCode != http.StatusOK && rsp.StatusCode != http.StatusNotFound {
		return nil, -1, errors.Errorf("GET %s: invalid response code: %d: %s", path, rsp.StatusCode, string(responseData))
	}
	if rsp.StatusCode == http.StatusNotFound {
		return nil, http.StatusNotFound, nil
	}
	var response commonPostResponse
	err = json.Unmarshal(responseData, &response)
	if err != nil {
		return nil, -1, errors.Wrapf(err, "GET %s: unable to unmarshal response. data: %s", path, string(responseData))
	}
	return response.Status, rsp.StatusCode, nil
}

func (c *GalebClient) waitStatusOK(resourceURI string) error {
	path := strings.TrimPrefix(resourceURI, c.ApiUrl)
	var timeout <-chan time.Time
	if c.WaitTimeout != 0 {
		timeout = time.After(c.WaitTimeout)
	}
	var mapStatus map[string]string
	var err error
	var statusCode int
loop:
	for {
		mapStatus, statusCode, err = c.fetchPathStatus(path)
		if err != nil {
			break
		}
		if c.containsStatus(mapStatus, STATUS_OK) || statusCode == http.StatusNotFound {
			return nil
		}
		select {
		case <-timeout:
			stringStatus, _ := json.Marshal(mapStatus)
			err = errors.Errorf("GET %s: timeout after %v waiting for status change from %s", path, c.WaitTimeout, stringStatus)
			break loop
		default:
			time.Sleep(500 * time.Millisecond)
		}
	}
	if err != nil {
		return err
	}
	return errors.Errorf("GET %s: invalid status %s", path, mapStatus)
}

func (c *GalebClient) containsStatus(status map[string]string, statusCheck string) (contains bool) {
	for _, value := range status {
		if value != statusCheck {
			return false
		}
	}
	return true
}
