package enhance

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// maxTokens is the reply budget. It stays within what the SDK allows for a
// non-streaming request.
const maxTokens = 16000

// fallbackModels accept server-side fallback with "fallbacks": "default": if
// the model's safety classifiers decline the request, the API retries it on
// the model Anthropic recommends instead of returning a refusal.
var fallbackModels = map[string]bool{
	"claude-fable-5-2":  true,
	"claude-fable-5-1":  true,
	"claude-opus-5-5":   true,
	"claude-opus-5":     true,
	"claude-sonnet-5-5": true,
}

type anthropicClient struct {
	client anthropic.Client
	model  string
}

// NewAnthropic returns a Client that calls the Claude Messages API with the
// official SDK. model "" means DefaultModel. apiKey "" leaves the SDK's own
// credential lookup (ANTHROPIC_API_KEY and friends) in charge.
func NewAnthropic(apiKey, model string) Client {
	if model == "" {
		model = DefaultModel
	}
	var opts []option.RequestOption
	if apiKey != "" {
		opts = append(opts, option.WithAPIKey(apiKey))
	}
	return &anthropicClient{client: anthropic.NewClient(opts...), model: model}
}

func (a *anthropicClient) Complete(ctx context.Context, system, prompt string) (string, error) {
	params := anthropic.BetaMessageNewParams{
		Model:     a.model,
		MaxTokens: maxTokens,
		System:    []anthropic.BetaTextBlockParam{{Text: system}},
		Messages: []anthropic.BetaMessageParam{
			anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(prompt)),
		},
	}
	if fallbackModels[a.model] {
		params.Fallbacks = anthropic.BetaFallbacksParamOfDefault()
		params.Betas = []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01}
	}
	msg, err := a.client.Beta.Messages.New(ctx, params)
	if err != nil {
		var apiErr *anthropic.Error
		if errors.As(err, &apiErr) {
			switch apiErr.StatusCode {
			case 401, 403:
				return "", fmt.Errorf("the Claude API rejected the credentials (HTTP %d); check ANTHROPIC_API_KEY: %w", apiErr.StatusCode, err)
			case 404:
				return "", fmt.Errorf("the Claude API does not know the model %q (HTTP 404); pick another with --model: %w", a.model, err)
			case 429:
				return "", fmt.Errorf("the Claude API is rate limiting this key (HTTP 429); try again later: %w", err)
			}
		}
		return "", fmt.Errorf("calling the Claude API: %w", err)
	}
	switch msg.StopReason {
	case anthropic.BetaStopReasonRefusal:
		return "", fmt.Errorf("Claude declined the request (refusal, category %q); nothing was changed", msg.StopDetails.Category)
	case anthropic.BetaStopReasonMaxTokens:
		return "", fmt.Errorf("Claude's reply hit the %d-token limit before it finished; nothing was changed (try a spec with fewer tools)", maxTokens)
	}
	var b strings.Builder
	for _, block := range msg.Content {
		if block.Type == "text" {
			b.WriteString(block.Text)
		}
	}
	if strings.TrimSpace(b.String()) == "" {
		return "", errors.New("Claude returned an empty reply; nothing was changed")
	}
	return b.String(), nil
}
