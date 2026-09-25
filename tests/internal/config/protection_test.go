package config_test

import (
	"context"
	"database/sql/driver"
	"errors"
	"jingshield/internal/config"
	"jingshield/tests/testdb"
	"testing"
)

func TestProfilesAreIndependentAndDoNotEnableMasterSwitch(t *testing.T) {
	profiles := config.ProtectionProfiles()
	for _, profile := range profiles {
		if _, ok := profile.Values["system_status"]; ok {
			t.Fatal("profile changes master switch")
		}
		if _, ok := profile.Values["file_check_status"]; ok {
			t.Fatal("profile includes unimplemented engine")
		}
	}
	profiles[0].Values["cc_protection_status"] = "0"
	if config.ProtectionProfiles()[0].Values["cc_protection_status"] != "1" {
		t.Fatal("profile map leaked mutation")
	}
	values := config.ProtectionDefaults()
	if config.ProtectionSnapshot(values)["profile"] != "standard" {
		t.Fatal("default profile not standard")
	}
	values["scanner_protection_status"] = "0"
	if config.ProtectionSnapshot(values)["profile"] != "custom" {
		t.Fatal("override should become custom")
	}
}

func TestBehaviorBoundaries(t *testing.T) {
	for _, entry := range [][3]string{{"behavior_window_seconds", "9", "10"}, {"behavior_threshold", "1", "2"}, {"behavior_block_seconds", "86401", "86400"}, {"behavior_mode", "silent", "observe"}, {"scanner_protection_status", "true", "1"}, {"policy_protection_status", "2", "0"}} {
		if config.ValidProtectionValue(entry[0], entry[1]) {
			t.Errorf("accepted %s=%s", entry[0], entry[1])
		}
		if !config.ValidProtectionValue(entry[0], entry[2]) {
			t.Errorf("rejected %s=%s", entry[0], entry[2])
		}
	}
	if config.ValidProtectionValue("api_key", "anything") {
		t.Fatal("secret key became writable")
	}
}

func TestSetManyPublishesOnlyAfterCommit(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit", true: "rollback"}[failure], func(t *testing.T) {
			steps := []testdb.Step{{Kind: "begin"}, {Kind: "exec", Contains: "INSERT INTO jyj_config", Check: func(args []driver.NamedValue) error {
				if args[0].Value != "behavior_mode" {
					return errors.New("unstable key order")
				}
				return nil
			}}, {Kind: "exec", Contains: "INSERT INTO jyj_config"}, {Kind: "commit"}}
			if failure {
				steps[2].Error = errors.New("simulated disk failure")
				steps[3].Kind = "rollback"
			}
			dynamic := config.NewDynamicConfig(testdb.Open(t, steps...))
			err := dynamic.SetMany(context.Background(), map[string]string{"scanner_protection_status": "0", "behavior_mode": "observe"})
			if failure {
				if err == nil || dynamic.Get("behavior_mode") != "" {
					t.Fatal("failed transaction leaked state")
				}
			} else if err != nil || dynamic.Get("behavior_mode") != "observe" {
				t.Fatalf("successful transaction not published: %v", err)
			}
		})
	}
}
