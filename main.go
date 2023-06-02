package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/palantir/tenablesc-client/tenablesc"
)

func main() {
	tscBaseURL := os.Getenv("TSC_BASE_URL")
	tscKey := os.Getenv("TSC_KEY")
	tscSecret := os.Getenv("TSC_SECRET")
	client := tenablesc.NewClient(tscBaseURL)
	client.SetAPIKey(tscKey, tscSecret)

	var res []tenablesc.VulnDetailsResult
	_, err := client.Analyze(&tenablesc.Analysis{
		Type: "vuln",
		Query: tenablesc.AnalysisQuery{
			Type:       "vuln",
			SourceType: "cumulative",
			Tool:       "vulndetails",
			Filters: []tenablesc.AnalysisFilter{
				{
					FilterName: "repository",
					Operator:   "=",
					Value: []map[string]string{
						{
							"id": "1",
						},
					},
				},
			},
		},
		SourceType:    "cumulative",
		SortField:     "score",
		SortDirection: "desc",
		StartOffset: "0",
		EndOffset: "1000",
	},
		&res,
	)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	d, err := json.Marshal(res)
	fmt.Println(string(d))
}
