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
	// fmt.Println(tscBaseURL)
	client.SetAPIKey(tscKey, tscSecret)

	var analysisResult []tenablesc.VulnSumIPResult

	// Composing the query structs is a combination of reading the docs
	// and using browser Developer Tools to identify the right fields by
	// building the queries in the UI.
	_, err := client.Analyze(&tenablesc.Analysis{
		Type: "vuln",
		Query: tenablesc.AnalysisQuery{
			Type:       "vuln",
			SourceType: "cumulative",
			Tool:       "sumip",
			Filters: []tenablesc.AnalysisFilter{
				{
					FilterName: "repository",
					Operator:   "=",
					Value: []map[string]string{
						{
							// if this weren't an example, I'd recommend looking up your
							// repo ID first. your accessible repos may vary.
							"id": "1",
						},
					},
				},
			},
		},
		SourceType:    "cumulative",
		SortField:     "score",
		SortDirection: "desc",
	},
		&analysisResult,
	)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	d, err := json.Marshal(analysisResult)
	fmt.Println(string(d))
}
