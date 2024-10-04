package jsonfilter

import (
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"
)

const (
	JsonFilterModeOr  = 0
	JsonFilterModeAnd = 1
)

type (
	JsonFilter struct {
		Mode int
		Ops  []JsonFilterOp
	}

	JsonFilterOp func(JsonFilterable) bool

	JsonFilterable interface{}
)

func ParseJsonFilter(s string) (JsonFilterOp, error) {
	var (
		fields map[string]interface{}
		err    error
		op     JsonFilterOp
	)

	s = strings.TrimSpace(s)
	if s == "" || s == "{}" {
		return emptyFilter, nil
	}

	err = json.Unmarshal([]byte(s), &fields)
	if err != nil {
		return nil, err
	}

	op, err = parseJsonFilterGroup(fields, JsonFilterModeAnd)
	return op, err
}

func ParseJsonFilterFromMap(fields map[string]interface{}) (JsonFilterOp, error) {
	op, err := parseJsonFilterGroup(fields, JsonFilterModeAnd)
	return op, err
}

func emptyFilter(JsonFilterable) bool {
	return true
}

func (f JsonFilter) Match(v JsonFilterable) bool {
	var r bool

	if len(f.Ops) == 0 {
		return false
	}

	if f.Mode == JsonFilterModeAnd {
		for _, op := range f.Ops {
			p := op(v)
			if !p {
				return false
			}
		}

		r = true
	} else {
		for _, op := range f.Ops {
			p := op(v)
			if p {
				return true
			}
		}

		r = false
	}

	return r
}

func parseJsonFilterGroup(fields map[string]interface{}, m int) (JsonFilterOp, error) {
	var (
		err error
		f   JsonFilter
		op  JsonFilterOp
	)

	f.Mode = m

	for k, v := range fields {
		if strings.HasPrefix(k, "$") {
			var subMode int

			switch k {
			case "$or":
				subMode = JsonFilterModeOr
			case "$and":
				subMode = JsonFilterModeAnd
			default:
				return nil, fmt.Errorf("invalid filter modificator, accepted values are $or and $and")
			}

			vm, ok := v.([]map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("invalid field content, expected list, got %T", v)
			}

			ff := JsonFilter{
				Mode: subMode,
				Ops:  nil,
			}

			for _, p := range vm {
				pp := p

				sop, err := parseJsonFilterGroup(pp, JsonFilterModeAnd)
				if err != nil {
					return nil, fmt.Errorf(err.Error())
				}
				ff.Ops = append(ff.Ops, sop)
			}

			op = func(v JsonFilterable) bool {
				return ff.Match(v)
			}

			//op, err = parseJsonFilterGroup(vm, subMode)
		} else {
			vm, ok := v.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("invalid field content")
			}

			op, err = parseJsonFilterOp(k, vm)
		}

		if err != nil {
			return nil, err
		}

		f.Ops = append(f.Ops, op)
	}

	fcn := func(v JsonFilterable) bool {
		return f.Match(v)
	}

	return fcn, nil
}

func parseJsonFilterOp(k string, v map[string]interface{}) (JsonFilterOp, error) {
	var (
		op  JsonFilterOp
		err error
	)

	if len(v) != 1 {
		return nil, fmt.Errorf("invalid filter, each field must have exactly one filter")
	}

	for fOp, fVal := range v {
		switch fOp {
		case "$eq":
			op, err = makeEqJsonFilter(k, fVal)
		case "$neq":
			op, err = makeNeqJsonFilter(k, fVal)
		case "$like":
			op, err = makeLikeJsonFilter(k, fVal)
		case "$lt":
			op, err = makeNumericComparision(k, fVal, func(a, b int64) bool {
				return a < b
			})
		case "$lte":
			op, err = makeNumericComparision(k, fVal, func(a, b int64) bool {
				return a <= b
			})
		case "$gt":
			op, err = makeNumericComparision(k, fVal, func(a, b int64) bool {
				return a > b
			})
		case "$gte":
			op, err = makeNumericComparision(k, fVal, func(a, b int64) bool {
				return a >= b
			})
		case "$network":
			op, err = makeNetworkJsonFilter(k, fVal)
		case "$contains":
			op, err = makeContainsJsonFilter(k, fVal)
		default:
			return nil, fmt.Errorf("unknown filter type")
		}
	}

	if err != nil {
		return nil, err
	}

	return op, nil
}

func makeEqJsonFilter(k string, v interface{}) (JsonFilterOp, error) {
	return func(i JsonFilterable) bool {
		return eqJsonFilter(i, k, v)
	}, nil
}

func makeNeqJsonFilter(k string, v interface{}) (JsonFilterOp, error) {
	return func(i JsonFilterable) bool {
		return !eqJsonFilter(i, k, v)
	}, nil
}

func eqJsonFilter(i JsonFilterable, k string, v interface{}) bool {
	targetData, err := GetField(i, k)
	if err != nil {
		return false
	}

	switch t := v.(type) {
	case string:
		convertedTargetData, err := convertToString(targetData)
		if err != nil {
			log.Printf("jsonfilter: could not convert target to string: %s\n", err)
			return false
		}

		return strings.EqualFold(t, convertedTargetData)
	case int64, float64, int, float32:
		convertedV, err := convertToInt64(v)
		if err != nil {
			log.Printf("jsonfilter: could not convert value to int64: %s\n", err)
			return false
		}

		convertedTargetData, err := convertToInt64(targetData)
		if err != nil {
			log.Printf("jsonfilter: could not convert target to int64: %s\n", err)
			return false
		}

		return convertedV == convertedTargetData
	case bool:
		convertedTargetData, err := convertToBool(targetData)
		if err != nil {
			log.Printf("jsonfilter: could not convert target to bool: %s\n", err)
			return false
		}

		return t == convertedTargetData
	}

	return false
}

func makeLikeJsonFilter(k string, v interface{}) (JsonFilterOp, error) {
	strV, ok := v.(string)
	if !ok {
		return nil, fmt.Errorf("invalid regexp value, must be a string")
	}

	r, err := regexp.Compile(strV)
	if err != nil {
		return nil, fmt.Errorf("invalid regexp: %w", err)
	}

	return func(i JsonFilterable) bool {
		return likeJsonFilter(i, k, r)
	}, nil
}

func likeJsonFilter(i JsonFilterable, k string, r *regexp.Regexp) bool {
	targetData, err := GetField(i, k)
	if err != nil {
		return false
	}

	strData, ok := targetData.(string)
	if !ok {
		return false
	}

	return r.MatchString(strData)
}

func makeNetworkJsonFilter(k string, v interface{}) (JsonFilterOp, error) {
	strTargetNetwork, ok := v.(string)
	if !ok {
		return nil, fmt.Errorf("invalid filter value: must be a string")
	}

	targetNetwork, err := netip.ParsePrefix(strTargetNetwork)
	if err != nil {
		return nil, fmt.Errorf("invalid filter value: not a network (%w)", err)
	}

	return func(i JsonFilterable) bool {
		return networkJsonFilter(i, k, &targetNetwork)
	}, nil
}

func networkJsonFilter(i JsonFilterable, k string, n *netip.Prefix) bool {
	value, err := GetField(i, k)
	if err != nil {
		return false
	}

	strIP, ok := value.(string)
	if !ok {
		return false
	}

	ip, err := netip.ParseAddr(strIP)
	if err != nil {
		return false
	}

	return n.Contains(ip)
}

func makeContainsJsonFilter(k string, v interface{}) (JsonFilterOp, error) {
	switch t := v.(type) {
	case string:
		return makeContainsJsonGenericFilter(k, t)
	case int:
		x := int64(t)
		return makeContainsJsonGenericFilter(k, x)
	case int32:
		x := int64(t)
		return makeContainsJsonGenericFilter(k, x)
	case int64:
		x := int64(t)
		return makeContainsJsonGenericFilter(k, x)
	case float32:
		x := int64(t)
		return makeContainsJsonGenericFilter(k, x)
	case float64:
		x := int64(t)
		return makeContainsJsonGenericFilter(k, x)
	}

	return nil, fmt.Errorf("invalid type for $contains filter")
}

func makeContainsJsonGenericFilter[T comparable](k string, v T) (JsonFilterOp, error) {
	return func(i JsonFilterable) bool {
		s, err := GetField(i, k)
		if err != nil {
			return false
		}

		slice, ok := s.([]T)
		if !ok {
			return false
		}

		return slices.Contains(slice, v)
	}, nil
}

func makeNumericComparision(k string, v interface{}, cmp func(a, b int64) bool) (JsonFilterOp, error) {
	return func(i JsonFilterable) bool {
		return numericJsonFilter(i, k, v, cmp)
	}, nil
}

func numericJsonFilter(i JsonFilterable, k string, v interface{}, cmp func(a, b int64) bool) bool {
	targetData, err := GetField(i, k)
	if err != nil {
		return false
	}

	nTargetData, err := convertToInt64(targetData)
	if err != nil {
		return false
	}

	nVal, err := convertToInt64(v)
	if err != nil {
		return false
	}

	return cmp(nTargetData, nVal)
}

func convertToString(v interface{}) (string, error) {
	switch t := v.(type) {
	case string:
		return t, nil
	case int64, int:
		return fmt.Sprintf("%d", t), nil
	case float64:
		return fmt.Sprintf("%d", int64(t)), nil
	case float32:
		return fmt.Sprintf("%d", int64(t)), nil
	case bool:
		val := v.(bool)
		if val {
			return "true", nil
		}

		return "false", nil
	}

	return "", fmt.Errorf("unknown source type for convertToString: %+t", v)
}

func convertToInt64(v interface{}) (int64, error) {
	switch t := v.(type) {
	case string:
		val, err := strconv.ParseInt(t, 10, 64)
		if err != nil {
			return 0, err
		}

		return val, nil
	case int64:
		return t, nil
	case int:
		return int64(t), nil
	case float64:
		return int64(t), nil
	case float32:
		return int64(t), nil
	case bool:
		val := t
		if val {
			return 1, nil
		}

		return 0, nil
	}

	return 0, fmt.Errorf("unknown source type for convertToInt64: %+t", v)
}

func convertToBool(v interface{}) (bool, error) {
	switch t := v.(type) {
	case string:
		val := t
		if val == "true" {
			return true, nil
		}
		if val == "false" {
			return false, nil
		}

		return false, fmt.Errorf("invalid literal for convertToBool: %s", val)
	case int64:
		val := t
		if val == 0 {
			return false, nil
		}
		if val == 1 {
			return true, nil
		}

		return false, fmt.Errorf("invalid numeric value for convertToBool: %d", val)
	case bool:
		return t, nil
	}

	return false, fmt.Errorf("unknown source type for convertToBool: %+t", v)
}

var ErrFieldNotPresent = fmt.Errorf("field is not present")

var TagNames = []string{
	"name", "json",
}

func GetField(item interface{}, name string) (interface{}, error) {
	if strings.Contains(name, ".") {
		p := strings.SplitN(name, ".", 2)

		first, err := GetField(item, p[0])
		if err != nil {
			return nil, err
		}

		return GetField(first, strings.Join(p[1:], "."))
	}

	t := reflect.TypeOf(item)
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	v := reflect.ValueOf(item)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}

	for i := 0; i < t.NumField(); i++ {
		for _, tagName := range TagNames {
			if tag, ok := t.Field(i).Tag.Lookup(tagName); ok {
				if tag == name {
					fieldVal := v.Field(i)
					val := fieldVal.Interface()
					return val, nil
				}
			}
		}

	}

	return nil, ErrFieldNotPresent
}
