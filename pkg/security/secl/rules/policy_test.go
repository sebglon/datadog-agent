// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package rules

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"

	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
)

func savePolicy(filename string, testPolicy *Policy) error {
	yamlBytes, err := yaml.Marshal(testPolicy)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, yamlBytes, 0700)
}

func TestMacroMerge(t *testing.T) {
	enabled := map[eval.EventType]bool{"*": true}
	var opts Opts
	opts.
		WithConstants(testConstants).
		WithSupportedDiscarders(testSupportedDiscarders).
		WithEventTypeEnabled(enabled).
		WithMacros(make(map[eval.MacroID]*eval.Macro))
	rs := NewRuleSet(&testModel{}, func() eval.Event { return &testEvent{} }, &opts)
	testPolicy := &Policy{
		Name: "test-policy",
		Macros: []*MacroDefinition{{
			ID:     "test_macro",
			Values: []string{"/usr/bin/vi"},
		}, {
			ID:      "test_macro",
			Values:  []string{"/usr/bin/vim"},
			Combine: MergePolicy,
		}},
	}

	tmpDir, err := ioutil.TempDir("", "test-policy")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	if err := savePolicy(filepath.Join(tmpDir, "test.policy"), testPolicy); err != nil {
		t.Fatal(err)
	}

	if err := LoadPolicies(tmpDir, rs); err != nil {
		t.Error(err)
	}

	macro := rs.GetMacros()["test_macro"]
	if macro == nil {
		t.Fatalf("failed to find test_macro in ruleset: %+v", rs.GetMacros())
	}

	sort.Strings(macro.Definition.Values)
	assert.Equal(t, []string{"/usr/bin/vi", "/usr/bin/vim"}, macro.Definition.Values)

	testPolicy.Macros[1].Combine = ""

	if err := savePolicy(filepath.Join(tmpDir, "test.policy"), testPolicy); err != nil {
		t.Fatal(err)
	}

	if err := LoadPolicies(tmpDir, rs); err == nil {
		t.Error("expected macro ID conflict")
	}
}

func TestRuleMerge(t *testing.T) {
	enabled := map[eval.EventType]bool{"*": true}
	var opts Opts
	opts.
		WithConstants(testConstants).
		WithSupportedDiscarders(testSupportedDiscarders).
		WithEventTypeEnabled(enabled).
		WithMacros(make(map[eval.MacroID]*eval.Macro))
	rs := NewRuleSet(&testModel{}, func() eval.Event { return &testEvent{} }, &opts)

	testPolicy := &Policy{
		Name: "test-policy",
		Rules: []*RuleDefinition{{
			ID:         "test_rule",
			Expression: `open.filename =~ "/sbin/*"`,
		}, {
			ID:         "test_rule",
			Expression: `&& process.uid != 0`,
			Combine:    MergePolicy,
		}},
	}

	tmpDir, err := ioutil.TempDir("", "test-policy")
	if err != nil {
		t.Fatal(err)
	}

	if err := savePolicy(filepath.Join(tmpDir, "test.policy"), testPolicy); err != nil {
		t.Fatal(err)
	}

	if err := LoadPolicies(tmpDir, rs); err != nil {
		t.Error(err)
	}

	rule := rs.GetRules()["test_rule"]
	if rule == nil {
		t.Fatal("failed to find test_rule in ruleset")
	}

	if expectedExpression := testPolicy.Rules[0].Expression + " " + testPolicy.Rules[1].Expression; rule.Expression != expectedExpression {
		t.Errorf("expected expression to be %s, got %s", expectedExpression, rule.Expression)
	}

	testPolicy.Rules[1].Combine = ""

	if err := savePolicy(filepath.Join(tmpDir, "test.policy"), testPolicy); err != nil {
		t.Fatal(err)
	}

	if err := LoadPolicies(tmpDir, rs); err == nil {
		t.Error("expected rule ID conflict")
	}
}

func TestMacroInRuleMerge(t *testing.T) {
	enabled := map[eval.EventType]bool{"*": true}
	var opts Opts
	opts.
		WithConstants(testConstants).
		WithSupportedDiscarders(testSupportedDiscarders).
		WithEventTypeEnabled(enabled).
		WithMacros(make(map[eval.MacroID]*eval.Macro))
	rs := NewRuleSet(&testModel{}, func() eval.Event { return &testEvent{} }, &opts)

	testPolicy := &Policy{
		Name: "test-policy",
		Macros: []*MacroDefinition{{
			ID:     "test_macro",
			Values: []string{"/usr/bin/vi"},
		}},
		Rules: []*RuleDefinition{{
			ID:         "test_rule",
			Expression: `open.filename in test_macro`,
		}},
	}

	tmpDir, err := ioutil.TempDir("", "test-policy")
	if err != nil {
		t.Fatal(err)
	}

	if err := savePolicy(filepath.Join(tmpDir, "test.policy"), testPolicy); err != nil {
		t.Fatal(err)
	}

	if err := LoadPolicies(tmpDir, rs); err != nil {
		t.Error(err)
	}

	rule := rs.GetRules()["test_rule"]
	if rule == nil {
		t.Fatal("failed to find test_rule in ruleset")
	}
}

type testStateScope struct {
	vars map[string]map[string]interface{}
}

func (t *testStateScope) GetVariable(name string, value interface{}) (eval.VariableValue, error) {
	switch value.(type) {
	case int:
		intVar := eval.NewIntVariable(func(ctx *eval.Context) int {
			processName := (*testEvent)(ctx.Object).process.name
			processVars, found := t.vars[processName]
			if !found {
				return 0
			}

			v, found := processVars[name]
			if !found {
				return 0
			}

			i, _ := v.(int)
			return i
		}, func(ctx *eval.Context, value interface{}) error {
			processName := (*testEvent)(ctx.Object).process.name
			if _, found := t.vars[processName]; !found {
				t.vars[processName] = map[string]interface{}{}
			}

			t.vars[processName][name] = value
			return nil
		})
		return intVar, nil
	default:
		return nil, fmt.Errorf("unsupported variable '%s'", name)
	}
}

func TestActionSetVariable(t *testing.T) {
	enabled := map[eval.EventType]bool{"*": true}
	stateScopes := map[Scope]StateScope{
		"process": &testStateScope{
			vars: map[string]map[string]interface{}{},
		},
	}
	var opts Opts
	opts.
		WithConstants(testConstants).
		WithSupportedDiscarders(testSupportedDiscarders).
		WithEventTypeEnabled(enabled).
		WithVariables(make(map[string]eval.VariableValue)).
		WithStateScopes(stateScopes).
		WithMacros(make(map[eval.MacroID]*eval.Macro))
	rs := NewRuleSet(&testModel{}, func() eval.Event { return &testEvent{} }, &opts)

	testPolicy := &Policy{
		Name: "test-policy",
		Rules: []*RuleDefinition{{
			ID:         "test_rule",
			Expression: `open.filename == "/tmp/test"`,
			Actions: []ActionDefinition{{
				Set: &SetDefinition{
					Name:  "var1",
					Value: true,
				},
			}, {
				Set: &SetDefinition{
					Name:  "var2",
					Value: "value",
				},
			}, {
				Set: &SetDefinition{
					Name:  "var3",
					Value: 123,
				},
			}, {
				Set: &SetDefinition{
					Name:  "var4",
					Value: 123,
					Scope: "process",
				},
			}, {
				Set: &SetDefinition{
					Name: "var5",
					Value: []string{
						"val1",
					},
				},
			}, {
				Set: &SetDefinition{
					Name: "var6",
					Value: []int{
						123,
					},
				},
			}},
		}, {
			ID:         "test_rule2",
			Expression: `open.filename == "/tmp/test2" && ${var1} == true && "${var2}" == "value" && ${var2} == "value" && ${var3} == 123 && ${process.var4} == 123 && "val1" in ${var5} && 123 in ${var6}`,
		}},
	}

	tmpDir, err := ioutil.TempDir("", "test-policy")
	if err != nil {
		t.Fatal(err)
	}

	if err := savePolicy(filepath.Join(tmpDir, "test.policy"), testPolicy); err != nil {
		t.Fatal(err)
	}

	if err := LoadPolicies(tmpDir, rs); err != nil {
		t.Error(err)
	}

	rule := rs.GetRules()["test_rule"]
	if rule == nil {
		t.Fatal("failed to find test_rule in ruleset")
	}

	fmt.Printf("%+v\n", rs.opts.Constants)

	event := &testEvent{
		process: testProcess{
			uid:  0,
			name: "myprocess",
		},
	}

	ev1 := *event
	ev1.kind = "open"
	ev1.open = testOpen{
		filename: "/tmp/test2",
		flags:    syscall.O_RDONLY,
	}

	if rs.Evaluate(event) {
		t.Errorf("Expected event to match no rule")
	}

	ev1.open.filename = "/tmp/test"

	if !rs.Evaluate(&ev1) {
		t.Errorf("Expected event to match rule")
	}

	ev1.open.filename = "/tmp/test2"
	if !rs.Evaluate(&ev1) {
		t.Errorf("Expected event to match rule")
	}
}
