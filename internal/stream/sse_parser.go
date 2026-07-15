package stream

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

type SSEEvent struct {
	Data string
	Event string
	ID string
	Retry int
}

type SSEParser struct {
	reader *bufio.Reader
}

func NewSSEParser(r io.Reader) *SSEParser {
	return &SSEParser{
		reader: bufio.NewReader(r),
	}
}

func (p *SSEParser) ReadEvent() (*SSEEvent, error) {
	event := &SSEEvent{}
	dataBuffer := &bytes.Buffer{}

	for {
		line, err := p.reader.ReadString('\n')
		if err != nil {
			if err == io.EOF && dataBuffer.Len() > 0 {
				event.Data = dataBuffer.String()
				return event, nil
			}
			return nil, err
		}

		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")

		if line == "" {
			if dataBuffer.Len() > 0 {
				event.Data = dataBuffer.String()
				return event, nil
			}
			continue
		}

		if strings.HasPrefix(line, "data:") {
			data := strings.TrimPrefix(line, "data:")
			data = strings.TrimSpace(data)
			if dataBuffer.Len() > 0 {
				dataBuffer.WriteByte('\n')
			}
			dataBuffer.WriteString(data)
		} else if strings.HasPrefix(line, "event:") {
			event.Event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		} else if strings.HasPrefix(line, "id:") {
			event.ID = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
		} else if strings.HasPrefix(line, "retry:") {
			retryStr := strings.TrimSpace(strings.TrimPrefix(line, "retry:"))
			if retryVal, err := strconv.Atoi(retryStr); err == nil {
				event.Retry = retryVal
			}
		}
	}
}

type ContentDelta struct {
	Content string `json:"content"`
}

type ChoiceDelta struct {
	Delta ContentDelta `json:"delta"`
	FinishReason string `json:"finish_reason"`
}

type SSEPayload struct {
	Choices []ChoiceDelta `json:"choices"`
}

func ExtractContentFromSSEData(data string) (string, bool) {
	if data == "" || data == "[DONE]" {
		return "", true
	}

	var payload SSEPayload
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		logrus.Debug("Failed to parse SSE data as JSON:", data)
		return "", false
	}

	if len(payload.Choices) == 0 {
		return "", false
	}

	return payload.Choices[0].Delta.Content, payload.Choices[0].FinishReason != ""
}