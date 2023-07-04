// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

// Action Group: Metadata
//
// Description:
// Assigns severity to the rule in which it is used.
// Severity values in Coraza follows the numeric scale of syslog (where 0 is the most severe).
//
// The data below is used by the OWASP Core Rule Set (CRS):
// - **0, EMERGENCY**: is generated from correlation of anomaly scoring data where there is an inbound attack and an outbound leakage.
// - **1, ALERT**: is generated from correlation where there is an inbound attack and an outbound application level error.
// - **2, CRITICAL**: Anomaly Score of 5. Is the highest severity level possible without correlation. It is normally generated by the web attack rules (40 level files).
// - **3, ERROR**: Error - Anomaly Score of 4. Is generated mostly from outbound leakage rules (50 level files).
// - **4, WARNING**: Anomaly Score of 3. Is generated by malicious client rules (35 level files).
// - **5, NOTICE**: Anomaly Score of 2. Is generated by the Protocol policy and anomaly files.
// - **6, INFO**
// - **7, DEBUG**
//
// > It is possible to specify severity levels using either the numerical values or the text values,
// > but you should always specify severity levels using the text values,
// > because it is difficult to remember what a number stands for.
// > The use of the numerical values is deprecated as of version 2.5.0 and may be removed in one of the subsequent major updates.
//
// Example:
// ```
// SecRule REQUEST_METHOD "^PUT$" "id:340002,rev:1,severity:CRITICAL,msg:'Restricted HTTP function'"
// ```
type severityFn struct{}

func (a *severityFn) Init(r plugintypes.RuleMetadata, data string) error {
	if len(data) == 0 {
		return ErrMissingArguments
	}

	sev, err := types.ParseRuleSeverity(data)
	if err != nil {
		return err
	}
	r.(*corazawaf.Rule).Severity_ = sev
	return nil
}

func (a *severityFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {}

func (a *severityFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeMetadata
}

func severity() plugintypes.Action {
	return &severityFn{}
}

var (
	_ plugintypes.Action = &severityFn{}
	_ ruleActionWrapper  = severity
)