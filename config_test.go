package kpx

import "testing"

func TestLoad(t *testing.T) {
	var config *Config
	var err error
	config, err = NewConfig("test-integration.json")
	if err != nil {
		t.Error(err)
	}
	println(config.conf.ConnectTimeout)
	println(config.conf.CloseTimeout)
	config, err = NewConfig("test-integration.yaml")
	if err != nil {
		t.Error(err)
	}
	println(config.conf.ConnectTimeout)
	println(config.conf.CloseTimeout)
	println(config.pac)
}
