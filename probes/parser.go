package probes

import (
	"bufio"
	"errors"
	"github.com/samber/lo"
	"io"
	"sort"
	"strconv"
	"strings"
)

func Parse(src io.Reader) (*Config, error) {
	scanner := bufio.NewScanner(src)
	var probes []*Probe
	config := &Config{}
	var currentProbe *Probe
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		index := strings.Index(line, " ")
		if index == -1 {
			println("Invalid line:", line)
			continue
		}

		var command = line[:index]
		var args = line[index+1:]
		if strings.EqualFold(command, "probe") {
			p, err := parseProb(args)
			if err != nil {
				return nil, errors.New("parse probes error: " + err.Error())
			}
			currentProbe = p
			probes = append(probes, p)
		} else if strings.EqualFold(command, "match") {
			m, err := parseMatch(args)
			if err != nil {
				return nil, err
			}
			if currentProbe == nil {
				return nil, errors.New("match found before probes")
			}
			currentProbe.Matches = append(currentProbe.Matches, m)
		} else if strings.EqualFold(command, "softmatch") {
			m, err := parseMatch(args)
			if err != nil {
				return nil, err
			}
			if currentProbe == nil {
				return nil, errors.New("softmatch found before probes")
			}
			currentProbe.SoftMatches = append(currentProbe.SoftMatches, m)
		} else if strings.EqualFold(command, "exclude") {
			ss := strings.Split(args, ",")
			for _, s := range ss {
				e, err := parseExclude(s)
				if err != nil {
					return nil, err
				}
				config.Exclude = append(config.Exclude, e)
			}
		} else if strings.EqualFold(command, "totalwaitms") {
			currentProbe.TotalWaitMs = parseInt(args)
		} else if strings.EqualFold(command, "tcpwrappedms") {
			currentProbe.TCPWrappedMs = parseInt(args)
		} else if strings.EqualFold(command, "rarity") {
			currentProbe.Rarity = parseInt(args)
		} else if strings.EqualFold(command, "ports") {
			currentProbe.Ports = parsePorts(args)
		} else if strings.EqualFold(command, "sslports") {
			currentProbe.SSLPorts = parsePorts(args)
		} else if strings.EqualFold(command, "fallback") {
			currentProbe.Fallbacks = strings.Split(args, ",")
		} else {
			panic("Unknown command: " + command)
		}
	}
	config.Probes = probes
	return config, nil
}

func parseInt(s string) int {
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return v
}

// 53,T:9100,U:30000-40000
func parseExclude(args string) (*PortRange, error) {
	var protocol string
	if strings.HasPrefix(args, "T:") {
		protocol = "tcp"
		args = args[2:]
	} else if strings.HasPrefix(args, "U:") {
		protocol = "udp"
		args = args[2:]
	}
	return &PortRange{
		Protocol: protocol,
		Ports:    parsePorts(args),
	}, nil
}

func parsePorts(args string) []int {
	var portMap = make(map[int]struct{})
	ss := strings.Split(args, ",")
	for _, s := range ss {
		ps := parsePort(s)
		if ps == nil {
			return nil
		}
		for _, p := range ps {
			portMap[p] = struct{}{}
		}
	}
	ports := lo.Keys(portMap)
	sort.Ints(ports)
	return ports
}

func parsePort(args string) []int {
	var rangeDelimiterIndex = strings.Index(args, "-")
	var ports []int
	if rangeDelimiterIndex == -1 {
		port, err := strconv.Atoi(args)
		if err != nil {
			return nil
		}
		ports = append(ports, port)
	} else {
		start, err := strconv.Atoi(args[:rangeDelimiterIndex])
		if err != nil {
			println("Invalid port:", args[:rangeDelimiterIndex])
			return nil
		}
		end, err := strconv.Atoi(args[rangeDelimiterIndex+1:])
		if err != nil {
			println("Invalid port:", args[rangeDelimiterIndex+1:])
			return nil
		}
		for i := start; i <= end; i++ {
			ports = append(ports, i)
		}
	}
	return ports
}

func parseProb(line string) (*Probe, error) {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 {
		return nil, errors.New("invalid probes line: not enough parts - " + line)
	}
	probe := &Probe{
		Options: make(map[string]string),
	}
	probe.Protocol = strings.ToLower(parts[0])
	probe.Name = parts[1]
	line = parts[2]
	if len(line) < 3 || line[0] != 'q' {
		return nil, errors.New("invalid probes line: no data")
	}
	delimiter := line[1]
	endIndex := strings.Index(line[2:], string(delimiter))
	if endIndex == -1 {
		return nil, errors.New("invalid probes line: no end delimiter (" + string(delimiter) + ")")
	}
	//probe.Data = decodeProbeData(line[2 : endIndex+2])
	probe.Data = line[2 : endIndex+2]
	line = strings.TrimSpace(line[endIndex+3:])
	opts := strings.Split(line, " ")
	for _, opt := range opts {
		if opt == "no-payload" {
			probe.NoPayload = true
		} else {
			eqIndex := strings.Index(opt, "=")
			if eqIndex == -1 {
				probe.Options[opt] = ""
			} else {
				probe.Options[opt[:eqIndex]] = opt[eqIndex+1:]
			}
		}
	}
	return probe, nil
}

func decodeProbeData(data string) []byte {
	var result []byte
	i := 0
	for i < len(data) {
		if data[i] == '\\' {
			i++
			switch data[i] {
			case '0':
				result = append(result, 0)
			case 'a':
				result = append(result, 7)
			case 'b':
				result = append(result, 8)
			case 'f':
				result = append(result, 12)
			case 'n':
				result = append(result, 10)
			case 'r':
				result = append(result, 13)
			case 't':
				result = append(result, 9)
			case 'v':
				result = append(result, 11)
			case 'x':
				if i+2 >= len(data) {
					panic("Invalid hex - " + data)
				} else {
					hex, err := strconv.ParseInt(data[i+1:i+3], 16, 16)
					if err != nil {
						panic("Invalid hex - " + err.Error())
					}
					result = append(result, byte(hex))
					i += 2
				}
			default:
				result = append(result, data[i])
			}
		} else {
			result = append(result, data[i])
		}
		i++

	}
	return result
}

func parseMatch(line string) (*ProbeMatch, error) {
	index := strings.Index(line, " ")
	if index == -1 {
		return nil, errors.New("invalid match line: no service")
	}
	match := &ProbeMatch{}
	match.Service = line[:index]
	line = line[index+1:]

	if len(line) == 0 || line[0] != 'm' {
		return nil, errors.New("invalid match line: no pattern")
	}

	line = line[1:]
	delimiter := line[0]
	endIndex := strings.Index(line[1:], string(delimiter))
	if endIndex == -1 {
		return nil, errors.New("invalid match line: no end delimiter (" + string(delimiter) + ")")
	}
	regex := line[1 : endIndex+1]
	line = line[endIndex+2:]
	var options string
	if line != "" && line[0] != ' ' {
		endIndex = strings.Index(line, " ")
		if endIndex == -1 {
			options = line
			line = ""
		} else {
			options = line[:endIndex]
			line = line[endIndex+1:]
		}
	}

	match.Pattern = Pattern{
		Regex:   regex,
		Options: options,
	}

	for {
		if line == "" {
			return match, nil
		}
		f := line[0]
		switch f {
		case ' ':
			line = line[1:]
		case 'p', 'v', 'i', 'h', 'o', 'd':
			delimiter = line[1]
			line = line[2:]
			endIndex = strings.Index(line, string(delimiter))
			if endIndex == -1 {
				return nil, errors.New("invalid match line: no end delimiter (" + string(delimiter) + ") for field (" + string(f) + ") - " + line)
			}
			value := line[:endIndex]
			line = line[endIndex+1:]
			switch f {
			case 'p':
				match.VendorProductName = value
			case 'v':
				match.Version = value
			case 'i':
				match.Info = value
			case 'h':
				match.Hostname = value
			case 'o':
				match.OperatingSystem = value
			case 'd':
				match.DeviceType = value
			}
		case 'c':
			// cpe:/cpename/[a]
			if strings.HasPrefix(line, "cpe:") {
				line = line[4:]
				delimiter = line[0]
				line = line[1:]
				endIndex = strings.Index(line, string(delimiter))
				if endIndex == -1 {
					return nil, errors.New("invalid match line: no end delimiter (" + string(delimiter) + ") for field cpe - " + line)
				}
				value := line[:endIndex]
				line = line[endIndex+1:]
				match.CPEs = append(match.CPEs, value)
				if len(line) != 0 && line[0] == 'a' {
					line = line[1:]
				}
			} else {
				return nil, errors.New("invalid match line: unknown field - " + line)
			}
		default:
			return nil, errors.New("invalid match line: unknown field (" + string(f) + ") - " + line)
		}
	}

}
