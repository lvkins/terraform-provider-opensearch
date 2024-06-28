package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/olivere/elastic/uritemplates"
	elastic7 "github.com/olivere/elastic/v7"
)

var saDetectorRuleSchema = map[string]*schema.Schema{
	"body": {
		Description: "The security analytics detector rule document containing a Sigma rule",
		Type:        schema.TypeString,
		Required:    true,
	},
	"category": {
		Description: "A category of the detector rule",
		Type:        schema.TypeString,
		Required:    true,
	},
}

func resourceOpenSearchSaDetectorRule() *schema.Resource {
	return &schema.Resource{
		Description: "Provides an OpenSearch security analytics detector rule. Please refer to the OpenSearch security analytics documentation for details.",
		Create:      resourceOpensearchSaDetectorRuleCreate,
		Read:        resourceOpensearchSaDetectorRuleRead,
		Update:      resourceOpensearchSaDetectorRuleUpdate,
		Delete:      resourceOpensearchSaDetectorRuleDelete,
		Schema:      saDetectorRuleSchema,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
	}
}

func resourceOpensearchSaDetectorRuleCreate(d *schema.ResourceData, m interface{}) error {
	res, err := resourceOpensearchPostSaDetectorRule(d, m)

	if err != nil {
		log.Printf("[INFO] Failed to put security analytics detector rule: %+v", err)
		return err
	}

	d.SetId(res.ID)
	log.Printf("[INFO] Object ID: %s", d.Id())

	return resourceOpensearchSaDetectorRuleRead(d, m)
}

func resourceOpensearchSaDetectorRuleRead(d *schema.ResourceData, m interface{}) error {
	res, err := resourceOpensearchSaDetectorRuleGet(d.Id(), m)

	if err != nil {
		if IsSearchNotFound(err) {
			log.Printf("[WARN] Security Analytics Detector Rule (%s) not found, removing from state", d.Id())
			d.SetId("")
			return nil
		}

		return err
	}

	d.SetId(res.ID)
	return d.Set("body", res.Rule["rule"])
}

func resourceOpensearchSaDetectorRuleUpdate(d *schema.ResourceData, m interface{}) error {
	_, err := resourceOpensearchPutSaDetectorRule(d, m)

	if err != nil {
		return err
	}

	return resourceOpensearchSaDetectorRuleRead(d, m)
}

func resourceOpensearchSaDetectorRuleGet(SaDetectorRuleID string, m interface{}) (*SaDetectorRuleResponse, error) {
	var err error
	response := new(SaDetectorRuleResponse)

	query := map[string]interface{}{
		"size": 1,
		"query": map[string]interface{}{
			"ids": map[string]interface{}{
				"values": []string{SaDetectorRuleID},
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
		Path:        "/_plugins/_security_analytics/rules/_search?pre_packaged=false",
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
		return response, fmt.Errorf("no search results found for ID: %s", SaDetectorRuleID)
	}

	var rule map[string]interface{}
	if err := json.Unmarshal(searchResult.Hits.Hits[0].Source, &rule); err != nil {
		return response, fmt.Errorf("error unmarshalling rule source: %+v", err)
	}

	response.ID = searchResult.Hits.Hits[0].ID
	response.Version = searchResult.Hits.Hits[0].Version
	response.Rule = rule

	log.Printf("[INFO] Response: %+v", response)
	log.Printf("The version %v", response.Version)
	return response, err
}

func resourceOpensearchPostSaDetectorRule(d *schema.ResourceData, m interface{}) (*SaDetectorRuleResponse, error) {
	SaDetectorRuleBody := d.Get("body").(string)
	Category := d.Get("category").(string)

	var err error
	response := new(SaDetectorRuleResponse)

	path, err := uritemplates.Expand("/_plugins/_security_analytics/rules?category={category}", map[string]string{
		"category": Category,
	})
	if err != nil {
		return response, fmt.Errorf("error building URL path for detector rule: %+v", err)
	}

	var body json.RawMessage
	osClient, err := getClient(m.(*ProviderConf))
	if err != nil {
		return nil, err
	}
	var res *elastic7.Response
	res, err = osClient.PerformRequest(context.TODO(), elastic7.PerformRequestOptions{
		Method:      "POST",
		Path:        path,
		Body:        SaDetectorRuleBody,
		ContentType: "application/json",
	})
	if err != nil {
		return response, err
	}
	body = res.Body

	if err := json.Unmarshal(body, response); err != nil {
		return response, fmt.Errorf("error unmarshalling detector rule body: %+v: %+v", err, body)
	}
	return response, nil
}

func resourceOpensearchPutSaDetectorRule(d *schema.ResourceData, m interface{}) (*SaDetectorRuleResponse, error) {
	SaDetectorRuleJSON := d.Get("body").(string)
	Category := d.Get("category").(string)

	var err error
	response := new(SaDetectorRuleResponse)

	path, err := uritemplates.Expand("/_plugins/_security_analytics/rules/{id}?category={category}&forced=true", map[string]string{
		"id":       d.Id(),
		"category": Category,
	})
	if err != nil {
		return response, fmt.Errorf("error building URL path for detector rule: %+v", err)
	}

	var body json.RawMessage
	osClient, err := getClient(m.(*ProviderConf))
	if err != nil {
		return nil, err
	}
	var res *elastic7.Response
	res, err = osClient.PerformRequest(context.TODO(), elastic7.PerformRequestOptions{
		Method:      "PUT",
		Path:        path,
		Body:        SaDetectorRuleJSON,
		ContentType: "application/json",
	})
	if err != nil {
		return response, err
	}
	body = res.Body

	if err := json.Unmarshal(body, response); err != nil {
		return response, fmt.Errorf("error unmarshalling detector rule body: %+v: %+v", err, body)
	}

	return response, nil
}

func resourceOpensearchSaDetectorRuleDelete(d *schema.ResourceData, m interface{}) error {
	var err error

	path, err := uritemplates.Expand("/_plugins/_security_analytics/rules/{id}?forced=true", map[string]string{
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

type SaDetectorRuleResponse struct {
	Version int                    `json:"_version"`
	ID      string                 `json:"_id"`
	Rule    map[string]interface{} `json:"rule"`
}

type SaDetectorRuleObject struct {
	Rule string `json:"rule"`
}
