package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/structure"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/olivere/elastic/uritemplates"
	elastic7 "github.com/olivere/elastic/v7"
)

var saDetectorSchema = map[string]*schema.Schema{
	"body": {
		Description:      "The security analytics detector document",
		Type:             schema.TypeString,
		Required:         true,
		DiffSuppressFunc: diffSuppressSaDetector,
		StateFunc: func(v interface{}) string {
			json, _ := structure.NormalizeJsonString(v)
			return json
		},
		ValidateFunc: validation.StringIsJSON,
	},
}

func resourceOpenSearchSaDetector() *schema.Resource {
	return &schema.Resource{
		Description: "Provides an OpenSearch security analytics detection. Please refer to the OpenSearch security analytics documentation for details.",
		Create:      resourceOpensearchSaDetectorCreate,
		Read:        resourceOpensearchSaDetectorRead,
		Update:      resourceOpensearchSaDetectorUpdate,
		Delete:      resourceOpensearchSaDetectorDelete,
		Schema:      saDetectorSchema,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
	}
}

func resourceOpensearchSaDetectorCreate(d *schema.ResourceData, m interface{}) error {
	res, err := resourceOpensearchPostSaDetector(d, m)

	if err != nil {
		log.Printf("[INFO] Failed to put security analytics detector: %+v", err)
		return err
	}

	d.SetId(res.ID)
	log.Printf("[INFO] Object ID: %s", d.Id())

	return resourceOpensearchSaDetectorRead(d, m)
}

func resourceOpensearchSaDetectorRead(d *schema.ResourceData, m interface{}) error {
	res, err := resourceOpensearchSaDetectorSearch(d.Id(), m)

	if err != nil {
		if IsSearchNotFound(err) {
			log.Printf("[WARN] Security Analytics Detector (%s) not found, removing from state", d.Id())
			d.SetId("")
			return nil
		}

		return err
	}

	d.SetId(res.ID)

	SaDetectorJSON, err := json.Marshal(res.Detector)
	if err != nil {
		return err
	}
	SaDetectorJsonNormalized, err := structure.NormalizeJsonString(string(SaDetectorJSON))
	if err != nil {
		return err
	}
	err = d.Set("body", SaDetectorJsonNormalized)
	return err
}

func resourceOpensearchSaDetectorUpdate(d *schema.ResourceData, m interface{}) error {
	_, err := resourceOpensearchPutSaDetector(d, m)

	if err != nil {
		return err
	}

	return resourceOpensearchSaDetectorRead(d, m)
}

func resourceOpensearchSaDetectorGet(SaDetectorID string, m interface{}) (*SaDetectorResponse, error) {
	var err error
	response := new(SaDetectorResponse)

	path, err := uritemplates.Expand("/_plugins/_security_analytics/detectors/{id}", map[string]string{
		"id": SaDetectorID,
	})
	if err != nil {
		return response, fmt.Errorf("error building URL path for detector: %+v", err)
	}

	var body json.RawMessage
	osClient, err := getClient(m.(*ProviderConf))
	if err != nil {
		return nil, err
	}
	var res *elastic7.Response
	res, err = osClient.PerformRequest(context.TODO(), elastic7.PerformRequestOptions{
		Method: "GET",
		Path:   path,
	})
	if err != nil {
		return response, err
	}
	body = res.Body

	if err := json.Unmarshal(body, response); err != nil {
		return response, fmt.Errorf("error unmarshalling detector body: %+v: %+v", err, body)
	}
	log.Printf("[INFO] Response: %+v", response)
	normalizeSaDetector(response.Detector)
	log.Printf("[INFO] Response: %+v", response)
	log.Printf("The version %v", response.Version)
	return response, err
}

func resourceOpensearchSaDetectorSearch(SaDetectorID string, m interface{}) (*SaDetectorResponse, error) {
	var err error
	response := new(SaDetectorResponse)

	query := map[string]interface{}{
		"size": 1,
		"query": map[string]interface{}{
			"ids": map[string]interface{}{
				"values": []string{SaDetectorID},
			},
		},
	}

	queryBody, err := json.Marshal(query)
	if err != nil {
		return response, fmt.Errorf("error marshalling query body: %+v", err)
	}

	log.Printf("[DEBUG] queryBody=%s", queryBody)

	osClient, err := getClient(m.(*ProviderConf))
	if err != nil {
		return nil, err
	}
	var res *elastic7.Response
	res, err = osClient.PerformRequest(context.TODO(), elastic7.PerformRequestOptions{
		Method:      "POST",
		Path:        "/_plugins/_security_analytics/detectors/_search",
		Body:        string(queryBody),
		ContentType: "application/json",
	})
	if err != nil {
		return response, err
	}

	var searchResult querySearchResult

	if err := json.Unmarshal(res.Body, &searchResult); err != nil {
		return response, fmt.Errorf("error unmarshalling search result: %+v", err)
	}

	if searchResult.Hits.Total.Value == 0 {
		return response, fmt.Errorf("no search results found for ID: %s", SaDetectorID)
	}

	var detector map[string]interface{}
	if err := json.Unmarshal(searchResult.Hits.Hits[0].Source, &detector); err != nil {
		return response, fmt.Errorf("error unmarshalling detector source: %+v", err)
	}

	response.ID = searchResult.Hits.Hits[0].ID
	response.Version = searchResult.Hits.Hits[0].Version
	response.Detector = detector
	log.Printf("[INFO] Response: %+v", response)
	normalizeSaDetector(response.Detector)
	log.Printf("[INFO] Response: %+v", response)
	log.Printf("The version %v", response.Version)
	return response, err
}

func resourceOpensearchPostSaDetector(d *schema.ResourceData, m interface{}) (*SaDetectorResponse, error) {
	SaDetectorJSON := d.Get("body").(string)

	var err error
	response := new(SaDetectorResponse)

	path := "/_plugins/_security_analytics/detectors"

	var body json.RawMessage
	osClient, err := getClient(m.(*ProviderConf))
	if err != nil {
		return nil, err
	}
	var res *elastic7.Response
	res, err = osClient.PerformRequest(context.TODO(), elastic7.PerformRequestOptions{
		Method: "POST",
		Path:   path,
		Body:   SaDetectorJSON,
	})
	if err != nil {
		return response, err
	}
	body = res.Body

	if err := json.Unmarshal(body, response); err != nil {
		return response, fmt.Errorf("error unmarshalling detector body: %+v: %+v", err, body)
	}
	normalizeSaDetector(response.Detector)
	return response, nil
}

func resourceOpensearchPutSaDetector(d *schema.ResourceData, m interface{}) (*SaDetectorResponse, error) {
	SaDetectorJSON := d.Get("body").(string)

	var err error
	response := new(SaDetectorResponse)

	path, err := uritemplates.Expand("/_plugins/_security_analytics/detectors/{id}", map[string]string{
		"id": d.Id(),
	})
	if err != nil {
		return response, fmt.Errorf("error building URL path for detector: %+v", err)
	}

	var body json.RawMessage
	osClient, err := getClient(m.(*ProviderConf))
	if err != nil {
		return nil, err
	}
	var res *elastic7.Response
	res, err = osClient.PerformRequest(context.TODO(), elastic7.PerformRequestOptions{
		Method: "PUT",
		Path:   path,
		Body:   SaDetectorJSON,
	})
	if err != nil {
		return response, err
	}
	body = res.Body

	if err := json.Unmarshal(body, response); err != nil {
		return response, fmt.Errorf("error unmarshalling detector body: %+v: %+v", err, body)
	}

	return response, nil
}

func resourceOpensearchSaDetectorDelete(d *schema.ResourceData, m interface{}) error {
	var err error

	path, err := uritemplates.Expand("/_plugins/_security_analytics/detectors/{id}", map[string]string{
		"id": d.Id(),
	})
	if err != nil {
		return fmt.Errorf("error building URL path for detector: %+v", err)
	}

	osClient, err := getClient(m.(*ProviderConf))
	if err != nil {
		return err
	}
	_, err = osClient.PerformRequest(context.TODO(), elastic7.PerformRequestOptions{
		Method: "DELETE",
		Path:   path,
	})

	return err
}

type SaDetectorResponse struct {
	Version  int                    `json:"_version"`
	ID       string                 `json:"_id"`
	Detector map[string]interface{} `json:"detector"`
}
