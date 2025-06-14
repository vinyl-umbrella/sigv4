package lambda

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"sigv4-lambda/sigv4"
)

type Client struct {
	signer     *sigv4.Signer
	httpClient *http.Client
	endpoint   string
	region     string
}

func NewClient(creds sigv4.Credentials, region string) (*Client, error) {
	signer := sigv4.NewSigner(creds)
	endpoint := fmt.Sprintf("https://lambda.%s.amazonaws.com", region)

	return &Client{
		signer:     signer,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		endpoint:   endpoint,
		region:     region,
	}, nil
}

type Function struct {
	FunctionName    string        `json:"FunctionName"`
	FunctionArn     string        `json:"FunctionArn"`
	Runtime         string        `json:"Runtime"`
	Role            string        `json:"Role"`
	Handler         string        `json:"Handler"`
	CodeSize        int64         `json:"CodeSize"`
	Description     string        `json:"Description"`
	Timeout         int           `json:"Timeout"`
	MemorySize      int           `json:"MemorySize"`
	LastModified    string        `json:"LastModified"`
	CodeSha256      string        `json:"CodeSha256"`
	Version         string        `json:"Version"`
	Environment     *EnvVariables `json:"Environment,omitempty"`
	DeadLetterQueue *Dlq          `json:"DeadLetterConfig,omitempty"`
	State           string        `json:"State"`
	StateReason     string        `json:"StateReason"`
}

type EnvVariables struct {
	Variables map[string]string `json:"Variables"`
}

type Dlq struct {
	TargetArn string `json:"TargetArn"`
}

type ListFunctionsResponse struct {
	Functions  []Function `json:"Functions"`
	NextMarker *string    `json:"NextMarker,omitempty"`
}

// InvokeApiParam is the request parameter for the Invoke API
type InvokeApiParam struct {
	FunctionName   string
	InvocationType string // Event || RequestResponse || DryRun
	LogType        string // None || Tail
	ClientContext  string
	Qualifier      string
	Payload        []byte
}

// InvokeResponse is the response for the Invoke API
type InvokeResponse struct {
	StatusCode      int               `json:"StatusCode"`
	FunctionError   string            `json:"FunctionError,omitempty"`
	LogResult       string            `json:"LogResult,omitempty"`
	Payload         []byte            `json:"Payload,omitempty"`
	ExecutedVersion string            `json:"ExecutedVersion,omitempty"`
	ResponseHeaders map[string]string `json:"ResponseHeaders,omitempty"`
}

// ListFunctions https://docs.aws.amazon.com/ja_jp/lambda/latest/api/API_ListFunctions.html
//
//	// maxItems: number of functions to return in the response
//	// marker: the pagination token that's returned by a previous request
func (c *Client) ListFunctions(ctx context.Context, maxItems *int, marker *string) (*ListFunctionsResponse, error) {
	u, err := url.Parse(c.endpoint + "/2015-03-31/functions")
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	query := u.Query()
	if maxItems != nil {
		query.Set("MaxItems", fmt.Sprintf("%d", *maxItems))
	}
	if marker != nil {
		query.Set("Marker", *marker)
	}
	u.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-amz-json-1.1")

	// sign
	if err := c.signer.SignRequest(req, "lambda", c.region); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	// send http request
	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer res.Body.Close()

	// read response body
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// check for non-200 status code
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error: %d - %s", res.StatusCode, string(body))
	}

	// parse response
	var listRes ListFunctionsResponse
	if err := json.Unmarshal(body, &listRes); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &listRes, nil
}

// Invoke https://docs.aws.amazon.com/ja_jp/lambda/latest/api/API_Invoke.html
func (c *Client) Invoke(ctx context.Context, req *InvokeApiParam) (*InvokeResponse, error) {
	u, err := url.Parse(fmt.Sprintf("%s/2015-03-31/functions/%s/invocations", c.endpoint, req.FunctionName))
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}
	if req.Qualifier != "" {
		query := u.Query()
		query.Set("Qualifier", req.Qualifier)
		u.RawQuery = query.Encode()
	}

	var body io.Reader
	if req.Payload != nil {
		body = bytes.NewReader(req.Payload)
	}

	// setup HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if req.InvocationType != "" {
		httpReq.Header.Set("X-Amz-Invocation-Type", req.InvocationType)
	} else {
		httpReq.Header.Set("X-Amz-Invocation-Type", "RequestResponse")
	}
	if req.LogType != "" {
		httpReq.Header.Set("X-Amz-Log-Type", req.LogType)
	}
	if req.ClientContext != "" {
		httpReq.Header.Set("X-Amz-Client-Context", req.ClientContext)
	}

	// sign the request
	if err := c.signer.SignRequest(httpReq, "lambda", c.region); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	// send the HTTP request
	res, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer res.Body.Close()

	// read response body
	respBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// parse the response headers
	responseHeaders := make(map[string]string)
	for key, values := range res.Header {
		if len(values) > 0 {
			responseHeaders[key] = values[0]
		}
	}

	// create the response
	invokeResp := &InvokeResponse{
		StatusCode:      res.StatusCode,
		Payload:         respBody,
		ResponseHeaders: responseHeaders,
	}

	// Extract specific headers
	if functionError := res.Header.Get("X-Amz-Function-Error"); functionError != "" {
		invokeResp.FunctionError = functionError
	}
	if logResult := res.Header.Get("X-Amz-Log-Result"); logResult != "" {
		invokeResp.LogResult = logResult
	}
	if executedVersion := res.Header.Get("X-Amz-Executed-Version"); executedVersion != "" {
		invokeResp.ExecutedVersion = executedVersion
	}

	return invokeResp, nil
}
