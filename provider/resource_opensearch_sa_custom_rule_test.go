package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccOpensearchSaCustomRule(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		Providers:    testAccOpendistroProviders,
		CheckDestroy: testCheckOpensearchSaCustomRuleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccOpensearchSaCustomRule,
				Check: resource.ComposeTestCheckFunc(
					testCheckOpensearchSaCustomRuleExists("opensearch_sa_custom_rule.test_rule"),
				),
			},
			{
				Config: testAccOpensearchSaCustomRuleUpdate,
				Check: resource.ComposeTestCheckFunc(
					testCheckOpensearchSaCustomRuleExists("opensearch_sa_custom_rule.test_rule"),
				),
			},
		},
	})
}

func testCheckOpensearchSaCustomRuleExists(name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("Not found: %s", name)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("No rule ID is set")
		}

		meta := testAccOpendistroProvider.Meta()

		var err error
		_, err = resourceOpensearchSaDetectorRuleGet(rs.Primary.ID, meta.(*ProviderConf))

		if err != nil {
			return err
		}

		return nil
	}
}

func testCheckOpensearchSaCustomRuleDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "opensearch_sa_custom_rule" {
			continue
		}

		meta := testAccOpendistroProvider.Meta()

		var err error
		_, err = resourceOpensearchSaDetectorRuleGet(rs.Primary.ID, meta.(*ProviderConf))

		if err != nil {
			return nil // should be not found error
		}

		return fmt.Errorf("Rule %q still exists", rs.Primary.ID)
	}

	return nil
}

var testAccOpensearchSaCustomRule = `
resource "opensearch_sa_custom_rule" "test_rule" {
  category   = "cloudtrail"
  body       = <<EOF
title: Test AWS CloudTrail IAM Access Denied Events
id: cb411bfe-e9f9-4eda-8276-414fe842261d
description: Detects AWS CloudTrail events where users receive an Access Denied error.
logsource:
  product: cloudtrail
tags:
  - attack.cloudtrail
  - attack.access-denied
falsepositives:
  - Administrative actions causing expected access denied errors
level: high
status: experimental
references: []
author: lvkins
date: 2024/06/19
modified: 2024/06/19
detection:
  condition: selection
  selection:
    eventSource:
      - iam.amazonaws.com
    errorCode:
      - AccessDenied
EOF
}
`

var testAccOpensearchSaCustomRuleUpdate = `
resource "opensearch_sa_custom_rule" "test_rule" {
  category   = "cloudtrail"
  body       = <<EOF
title: Test AWS CloudTrail IAM Access Denied Events
id: cb411bfe-e9f9-4eda-8276-414fe842261d
description: Detects AWS CloudTrail events where users receive an Access Denied error from IAM.
logsource:
  product: cloudtrail
tags:
  - attack.cloudtrail
  - attack.access-denied
falsepositives:
  - Administrative actions causing expected access denied errors
level: high
status: experimental
references: []
author: lvkins
date: 2024/06/19
modified: 2024/06/19
detection:
  condition: selection
  selection:
    eventSource:
      - iam.amazonaws.com
    errorCode:
      - AccessDenied
EOF
}
`
