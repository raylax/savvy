package util

import (
	"strconv"
	"strings"
)

func ParsePorts(ports string) []int {
	var ps []int
	for _, port := range strings.Split(ports, ",") {
		if port == "" {
			continue
		}
		if strings.Contains(port, "-") {
			r := strings.Split(port, "-")
			start, err := strconv.Atoi(r[0])
			if err != nil {
				panic(err)
			}
			end, err := strconv.Atoi(r[1])
			if err != nil {
				panic(err)
			}
			for i := start; i <= end; i++ {
				ps = append(ps, i)
			}
		} else {
			i, err := strconv.Atoi(port)
			if err != nil {
				panic(err)
			}
			ps = append(ps, i)
		}
	}
	return ps
}
