package bouncer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	johari "github.com/sinkingpoint/johari-go/lib"
)

type deciderTemplate struct {
	requiredConfigVars []string
	templateFunc       func(map[string]string) Decider
}

var deciderTemplates map[string]deciderTemplate

// InitDeciderTemplates sets up the bouncerTemplates map
// allowing finding a bouncerTemplate by a given name. Used to
// deserialize a list of bouncers
func InitDeciderTemplates() {
	deciderTemplates = map[string]deciderTemplate{
		"AllSilencesHaveAuthor": {
			requiredConfigVars: []string{"domain"},
			templateFunc:       AllSilencesHaveAuthorDecider,
		},
		"Mirror": {
			requiredConfigVars: []string{"destination"},
			templateFunc:       MirrorDecider,
		},
		"SilencesDontExpireOnWeekends": {
			requiredConfigVars: []string{},
			templateFunc:       SilencesDontExpireOnWeekendsDecider,
		},
		"LongSilencesHaveTicket": {
			requiredConfigVars: []string{"maxLength"},
			templateFunc:       LongSilencesHaveTicketDecider,
		},
	}
}

type matcher struct {
	IsRegex bool   `json:"isRegex"`
	Name    string `json:"name"`
	Value   string `json:"value"`
}

// alertmanagerSilenceSerialized represents a serialized silence from amtool in JSON
// e.g.
// {
//   "comment": "test",
//   "createdBy": "colin@quirl.co.nz",
//   "endsAt": "2020-01-13T16:34:49.444Z",
//   "matchers": [
//     {
//       "isRegex": false,
//       "name": "cats",
//       "value": "cats"
//     }
//   ],
//   "startsAt": "2020-01-13T15:34:49.444Z"
// }
type alertmanagerSilenceSerialized struct {
	Comment  string    `json:"comment"`
	Author   string    `json:"createdBy"`
	StartsAt string    `json:"startsAt"`
	EndsAt   string    `json:"endsAt"`
	Matchers []matcher `json:"matchers"`
}

// AlertmanagerSilence represents a Silence to be applied to Alertmanager
type AlertmanagerSilence struct {
	Comment  string
	Author   string
	StartsAt time.Time
	EndsAt   time.Time
	Matchers []matcher
}

func parseAlertmanagerSilence(body io.ReadCloser) (AlertmanagerSilence, error) {
	bodyBytes, err := ioutil.ReadAll(body)
	if err != nil {
		return AlertmanagerSilence{}, fmt.Errorf("Failed to read body")
	}
	serialized := alertmanagerSilenceSerialized{}
	json.Unmarshal(bodyBytes, &serialized)
	startTime, err := time.Parse(time.RFC3339, serialized.StartsAt)
	if err != nil {
		return AlertmanagerSilence{}, fmt.Errorf("Start Time %s is not a valid RFC3339 time string", serialized.StartsAt)
	}
	endTime, err := time.Parse(time.RFC3339, serialized.EndsAt)
	if err != nil {
		return AlertmanagerSilence{}, fmt.Errorf("End Time %s is not a valid RFC3339 time string", serialized.EndsAt)
	}

	return AlertmanagerSilence{
		Comment:  serialized.Comment,
		Author:   serialized.Author,
		StartsAt: startTime,
		EndsAt:   endTime,
		Matchers: serialized.Matchers,
	}, nil
}

// AllSilencesHaveAuthorDecider returns a decider that rejects requests that
// do not have authors which end in the given domain string
func AllSilencesHaveAuthorDecider(config map[string]string) Decider {
	return func(req *http.Request, context context.Context) *HTTPError {
		domain := config["domain"]
		silence, err := parseAlertmanagerSilence(req.Body)
		if err != nil {
			return &HTTPError{
				Status: 400,
				Err:    err,
			}
		}

		if !strings.HasSuffix(silence.Author, domain) {
			return &HTTPError{
				Status: 400,
				Err:    fmt.Errorf("Authors must be %s emails. Got %s", domain, silence.Author),
			}
		}

		return nil
	}
}

// MirrorDecider is a Decider which mirrors requests that it receives
// to an alternate location. This can be used for e.g. to spin up testing
// alertmanagers which receive everything a production one does
func MirrorDecider(config map[string]string) Decider {
	destination := config["destination"]
	return func(req *http.Request, context context.Context) *HTTPError {
		url := destination + req.RequestURI
		request, err := johari.NewChildRequest(
			context,
			req.Method,
			url,
			req.Body,
		)

		if err != nil {
			return &HTTPError{
				Status: 500,
				Err:    fmt.Errorf("Failed to create request to %s: %s", url, err),
			}
		}

		for name, values := range req.Header {
			for _, value := range values {
				request.Header.Add(name, value)
			}
		}

		log.Printf("Mirroring request to %s\n", destination)

		johari.NewHTTPClientWrapper(http.DefaultClient).Do(request)
		return nil
	}
}

// SilencesDontExpireOnWeekendsDecider returns a Decider which rejects silences
// that expire on weekends, so that we don't spring any surprises on someone oncall over the weekend
func SilencesDontExpireOnWeekendsDecider(config map[string]string) Decider {
	return func(req *http.Request, context context.Context) *HTTPError {
		silence, err := parseAlertmanagerSilence(req.Body)
		if err != nil {
			return &HTTPError{
				Status: 400,
				Err:    err,
			}
		}

		weekday := silence.EndsAt.Weekday()
		if weekday == time.Saturday || weekday == time.Sunday {
			return &HTTPError{
				Status: 400,
				Err:    fmt.Errorf("By policy, silences can't expire on weekends. Be nice to people oncall over the weekend! "),
			}
		}

		return nil
	}
}

// LongSilencesHaveTicketDecider returns a Decider which rejects silences longer than
// the given duration, which don't have a comment matching the "ticket_regex" (defaults to a JIRA ticket format)
// This allows us to not have long running throwaway silences without a ticket to track ongoing work
func LongSilencesHaveTicketDecider(config map[string]string) Decider {
	maxLengthWithoutTicket, err := time.ParseDuration(config["maxLength"])
	if err != nil {
		log.Printf("Failed to parse LongSilencesHaveTicket duration: %s", err)
		return nil
	}

	var ticketRegexStr string
	if regex, ok := config["ticketRegex"]; ok {
		ticketRegexStr = regex
	} else {
		ticketRegexStr = "[A-Z]+-[0-9]+"
	}

	ticketRegex, err := regexp.Compile(ticketRegexStr)
	if err != nil {
		log.Printf("Failed to parse LongSilencesHaveTicket ticket regex: %s", err)
		return nil
	}

	return func(req *http.Request, context context.Context) *HTTPError {
		silence, err := parseAlertmanagerSilence(req.Body)
		if err != nil {
			return &HTTPError{
				Status: 400,
				Err:    err,
			}
		}

		tooLong := silence.EndsAt.Sub(silence.StartsAt) > maxLengthWithoutTicket
		hasTicket := ticketRegex.MatchString(silence.Comment)

		if tooLong && !hasTicket {
			return &HTTPError{
				Status: 400,
				Err:    fmt.Errorf("Silences longer than %s must have tickets attached to them to track ongoing work", maxLengthWithoutTicket),
			}
		}

		return nil
	}
}
