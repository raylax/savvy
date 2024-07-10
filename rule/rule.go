package rule

import (
	"bufio"
	"errors"
	"github.com/raylax/savvy/util"
	"github.com/samber/lo"
	"gopkg.in/yaml.v3"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

var tcpRules Rules
var udpRules Rules
var servicePorts ServicePorts

func GetServicePorts() ServicePorts {
	return servicePorts
}

func GetTcpServicePorts() ServicePorts {
	return lo.Filter(servicePorts, func(sp *ServicePort, i int) bool {
		return sp.Protocol == "tcp"
	})
}

func GetUdpServicePorts() ServicePorts {
	return lo.Filter(servicePorts, func(sp *ServicePort, i int) bool {
		return sp.Protocol == "udp"
	})
}

func LoadServicePorts(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		ss := strings.SplitN(line, "\t", 4)
		if len(ss) < 3 {
			panic("Invalid service port line: " + line)
		}
		ps := strings.Split(ss[1], "/")
		port, err := strconv.Atoi(ps[0])
		if err != nil {
			panic("Invalid service port: " + ps[0])
		}
		openFrequency, err := strconv.ParseFloat(ss[2], 32)
		fullName := ""
		if len(ss) > 3 {
			fullName = strings.TrimSpace(ss[3][1:])
		}

		servicePorts = append(servicePorts, &ServicePort{
			Name:          ss[0],
			Port:          port,
			Protocol:      ps[1],
			OpenFrequency: float32(openFrequency),
			FullName:      fullName,
		})

	}

	sort.Sort(servicePorts)

	logger.Info("Service ports loaded", "count", len(servicePorts))

	return nil
}

func GetUdpRules(port int) Queue {
	var protRules portFirstRules
	for _, r := range udpRules {
		order := math.MaxInt
		if lo.Contains(util.ParsePorts(r.Ports), port) {
			order = orderPlain
		}
		protRules = append(protRules, portFirstRuleWrapper{
			Rule:  r,
			Order: order,
		})
	}
	return toTaskRules(protRules)
}

func GetTcpRules(port int) Queue {
	var protRules portFirstRules
	for _, r := range tcpRules {
		sslProts := util.ParsePorts(r.SSLPorts)
		if lo.Contains(sslProts, port) {
			protRules = append(protRules, portFirstRuleWrapper{
				Rule:  r,
				SSL:   true,
				Order: orderSSL,
			})
		}
		plainProts := util.ParsePorts(r.Ports)
		if lo.Contains(plainProts, port) {
			protRules = append(protRules, portFirstRuleWrapper{
				Rule:  r,
				SSL:   false,
				Order: orderPlain,
			})
		}
		protRules = append(protRules, portFirstRuleWrapper{
			Rule:  r,
			SSL:   false,
			Order: math.MaxInt,
		})
	}
	return toTaskRules(protRules)
}

func toTaskRules(portFirstRules portFirstRules) Queue {
	sort.Sort(portFirstRules)
	rules := Queue{}
	for _, r := range portFirstRules {
		rules.Push(&TaskRule{
			Rule: r.Rule,
			SSL:  r.SSL,
		})
	}
	return rules
}

func LoadRules(dir string) error {
	logger.Info("Loading rules", "dir", dir)
	matches, err := filepath.Glob(filepath.Join(dir, "SR_*.yml"))
	if err != nil {
		return err
	}
	sort.Strings(matches)

	for _, match := range matches {
		err = loadRule(match)
		if err != nil {
			return err
		}
	}

	sort.Sort(tcpRules)
	sort.Sort(udpRules)
	logger.Info("Rules loaded", "tcp", len(tcpRules), "udp", len(udpRules))
	return nil
}

func loadRule(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	r := &Rule{}
	err = yaml.NewDecoder(f).Decode(r)
	if err != nil {
		return errors.New("Error loading rule: " + file + " - " + err.Error())
	}
	switch r.Protocol {
	case "tcp":
		tcpRules = append(tcpRules, r)
	case "udp":
		udpRules = append(udpRules, r)
	default:
		panic("Unknown rule protocol: " + r.Protocol)
	}
	return nil
}
