package app

func dlpScopeOptions() DLPScopeOptions {
	options := DLPScopeOptions{Browsers: []DLPScopeChoice{{"chrome", "Chrome"}, {"edge", "Edge"}, {"firefox", "Firefox"}, {"brave", "Brave"}, {"chromium", "Chromium"}}, Services: []DLPScopeChoice{}, Applications: dlpNativeChoices()}
	factory, err := decodeDetection(detectionFactory)
	if err == nil {
		restrictEditionProviders(&factory)
		for _, provider := range factory.Providers {
			label := provider.Label
			switch provider.ID {
			case "chatgpt":
				label = "ChatGPT"
			case "claude":
				label = "Claude"
			}
			options.Services = append(options.Services, DLPScopeChoice{provider.ID, label})
		}
	}
	return options
}
