package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"sigv4-lambda/lambda"
	"sigv4-lambda/sigv4"
)

func main() {
	creds := sigv4.Credentials{
		AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		slog.Error("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set in environment variables.")
	}

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "ap-northeast-1"
	}
	fmt.Printf("AWS Region: %s\n", region)

	client, err := lambda.NewClient(creds, region)
	if err != nil {
		slog.Error("failed to create Lambda client", "error", err)
	}

	ctx := context.Background()

	fmt.Println("\n=== List Lambda Functions ===")
	if err := listFunctions(ctx, client); err != nil {
		slog.Error("failed to list functions", "error", err)
	}

	functionName := os.Getenv("LAMBDA_FUNCTION_NAME")
	if functionName != "" {
		fmt.Printf("\n=== Invoke Function: %s ===\n", functionName)
		if err := invokeFunction(ctx, client, functionName); err != nil {
			slog.Error("failed to invoke function", "functionName", functionName, "error", err)
		}
	}
}

func listFunctions(ctx context.Context, client *lambda.Client) error {
	maxFunctions := 10
	res, err := client.ListFunctions(ctx, &maxFunctions, nil)
	if err != nil {
		return fmt.Errorf("ListFunctions Error: %w", err)
	}

	for i, fn := range res.Functions {
		fmt.Printf("--------- Function %d ---------\n", i+1)
		fmt.Printf("Name:           %s\n", fn.FunctionName)
		fmt.Printf("Runtime:        %s\n", fn.Runtime)
		fmt.Printf("Handler:        %s\n", fn.Handler)
		fmt.Printf("Memory Size:    %d MB\n", fn.MemorySize)
		fmt.Printf("Timeout:        %d seconds\n", fn.Timeout)
		fmt.Printf("Last Modified:  %s\n", fn.LastModified)
		fmt.Printf("State:          %s\n", fn.State)

		if fn.Description != "" {
			fmt.Printf("Description:    %s\n", fn.Description)
		}
		fmt.Println()
	}
	if res.NextMarker != nil {
		fmt.Printf("Next Marker: %s\n", *res.NextMarker)
	}
	return nil
}

func invokeFunction(ctx context.Context, client *lambda.Client, functionName string) error {
	lambdaPayload := map[string]interface{}{
		"message":   "Hello from custom SigV4 Lambda client!",
		"timestamp": "2025-06-14T00:00:00Z",
		"test":      true,
	}
	payloadBytes, _ := json.Marshal(lambdaPayload)
	invokeReq := &lambda.InvokeApiParam{
		FunctionName:   functionName,
		InvocationType: "RequestResponse",
		LogType:        "Tail",
		Payload:        payloadBytes,
	}
	res, err := client.Invoke(ctx, invokeReq)
	if err != nil {
		return fmt.Errorf("invoke api response: %w", err)
	}

	fmt.Printf("StatusCode: %d\n", res.StatusCode)
	if res.FunctionError != "" {
		fmt.Printf("FunctionError: %s\n", res.FunctionError)
	}
	if res.Payload != nil {
		fmt.Printf("Response:\n")
		var responseJson interface{}
		if err := json.Unmarshal(res.Payload, &responseJson); err != nil {
			fmt.Printf("%s\n", string(res.Payload))
		} else {
			prettyJson, err := json.MarshalIndent(responseJson, "    ", "  ")
			if err != nil {
				fmt.Printf("%s\n", string(res.Payload))
			} else {
				fmt.Printf("%s\n", string(prettyJson))
			}
		}
	}
	if res.LogResult != "" {
		decodedLogs, err := base64.StdEncoding.DecodeString(res.LogResult)
		if err != nil {
			fmt.Printf("Failed to decode logs: %v\n", err)
		} else {
			fmt.Printf("Logs:\n%s\n", string(decodedLogs))
		}
	}
	return nil
}
