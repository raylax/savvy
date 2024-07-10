package scan

import (
	"github.com/raylax/savvy/rule"
	"github.com/raylax/savvy/util"
	"github.com/samber/lo"
	"go.elara.ws/pcre"
	"regexp"
	"strconv"
)

func matchServices(r *rule.TaskRule, bytes []byte) *Result {
	for _, s := range r.Services {
		result := matchService(s, bytes)
		if result != nil {
			return result
		}
	}

	for _, s := range r.FallbackServices {
		result := matchService(s, bytes)
		if result != nil {
			result.Fallback = true
			return result
		}
	}

	return nil
}

func matchService(s rule.Service, bytes []byte) *Result {

	var options pcre.CompileOption
	for i := 0; i < len(s.Pattern.Options); i++ {
		switch s.Pattern.Options[i] {
		case 'i':
			options |= pcre.Caseless
		case 's':
			options |= pcre.DotAll
		default:
			panic("unknown regex option: " + string(s.Pattern.Options[i]))
		}
	}

	pattern := pcre.MustCompileOpts(s.Pattern.Regex, pcre.DotAll|pcre.Caseless)
	matches := pattern.FindSubmatch(bytes)

	if matches == nil {
		return nil
	}

	result := &Result{
		Banner:  util.EncodeBannerString(bytes),
		Service: s.Name,
	}
	if s.Product != "" {
		result.Product = formatServiceField(matches, s.Product)
	}
	if s.Version != "" {
		result.Version = formatServiceField(matches, s.Version)
	}
	if s.Info != "" {
		result.Info = formatServiceField(matches, s.Info)
	}
	if s.Hostname != "" {
		result.Hostname = formatServiceField(matches, s.Hostname)
	}
	if s.OS != "" {
		result.OS = formatServiceField(matches, s.OS)
	}
	if s.DeviceType != "" {
		result.DeviceType = formatServiceField(matches, s.DeviceType)
	}
	if s.CPEs != nil {
		result.CEPs = lo.Map(s.CPEs, func(s string, i int) string {
			return formatServiceField(matches, s)
		})
	}

	return result
}

func formatServiceField(matches [][]byte, data string) string {
	var r = regexp.MustCompile(`\$(\d+)`)
	return r.ReplaceAllStringFunc(data, func(s string) string {
		i, _ := strconv.Atoi(s[1:])
		if i < len(matches) {
			return util.EncodeBinaryString(matches[i])
		} else {
			return s
		}
	})
}
