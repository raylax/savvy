package rule

import (
	"github.com/raylax/savvy/log"
	"github.com/raylax/savvy/util"
	"github.com/samber/lo"
	"slices"
	"strings"
)

var logger = log.Root.With("module", "rule")

const (
	orderSSL = iota
	orderPlain
)

type Rules []*Rule

func (r Rules) Len() int {
	return len(r)
}

func (r Rules) Less(i, j int) bool {
	return r[i].Rarity < r[j].Rarity
}

func (r Rules) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

type portFirstRuleWrapper struct {
	Rule  *Rule
	SSL   bool
	Order int
}

type portFirstRules []portFirstRuleWrapper

func (r portFirstRules) Len() int {
	return len(r)
}

func (r portFirstRules) Less(i, j int) bool {
	if r[i].Order < r[j].Order {
		return true
	}
	if r[i].Order > r[j].Order {
		return false
	}
	return r[i].Rule.Rarity < r[j].Rule.Rarity
}

func (r portFirstRules) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

type Queue struct {
	rules []*TaskRule
}

func (r *Queue) Pop() *TaskRule {
	if len(r.rules) == 0 {
		return nil
	}
	rule := r.rules[0]
	r.rules = r.rules[1:]
	return rule
}

func (r *Queue) Push(rule *TaskRule) {
	r.rules = append(r.rules, rule)
}

func (r *Queue) PushFront(rule *TaskRule) {
	r.rules = append([]*TaskRule{rule}, r.rules...)
}

func (r *Queue) Names() []string {
	return lo.Map(r.rules, func(rule *TaskRule, i int) string {
		if rule.SSL {
			return rule.Name + "(SSL)"
		}

		return rule.Name
	})
}

func (r *Queue) Find(name string) *TaskRule {
	name = strings.TrimSpace(name)
	for _, rule := range r.rules {
		if rule.Name == name {
			return rule
		}
	}
	return nil

}

type TaskRule struct {
	SSL bool
	*Rule
}

type Rule struct {
	Name             string
	Protocol         string
	Rarity           int
	Payload          string    `yaml:"payload,omitempty"`
	Ports            string    `yaml:"ports,omitempty"`
	SSLPorts         string    `yaml:"ssl-ports,omitempty"`
	Fallbacks        string    `yaml:"fallbacks,omitempty"`
	Services         []Service `yaml:"services,omitempty"`
	FallbackServices []Service `yaml:"fallback-services,omitempty"`
}

func (r *Rule) IsSSLPort(port int) bool {
	return slices.Contains(util.ParsePorts(r.SSLPorts), port)
}

type Pattern struct {
	Regex   string
	Options string `yaml:"options,omitempty"`
}

type Service struct {
	Name       string
	Pattern    Pattern
	Product    string   `yaml:"product,omitempty"`
	Version    string   `yaml:"version,omitempty"`
	Info       string   `yaml:"info,omitempty"`
	Hostname   string   `yaml:"hostname,omitempty"`
	OS         string   `yaml:"os,omitempty"`
	DeviceType string   `yaml:"device-type,omitempty"`
	CPEs       []string `yaml:"cpes,omitempty"`
}

type ServicePort struct {
	Port          int
	Name          string
	FullName      string
	Protocol      string
	OpenFrequency float32
}

type ServicePorts []*ServicePort

func (s ServicePorts) Len() int {
	return len(s)
}

func (s ServicePorts) Less(i, j int) bool {
	return s[i].OpenFrequency > s[j].OpenFrequency
}

func (s ServicePorts) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
