package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// =================================================================================
// 1. Configuration Management
// =================================================================================

// Config holds the application's configuration.
type Config struct {
	URL    string `json:"url"`
	APIKey string `json:"apiKey"`
}

var configDir string
var configFile string

// init sets up the configuration path before main() runs.
func init() {
	userConfigDir, err := os.UserConfigDir()
	if err != nil {
		fmt.Println("Error: Could not find user config directory:", err)
		os.Exit(1)
	}
	configDir = filepath.Join(userConfigDir, "cracker-client")
	configFile = filepath.Join(configDir, "config.json")
}

// loadConfig loads the configuration from the file, or creates it if it doesn't exist.
func loadConfig() (*Config, error) {
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		fmt.Println("Configuration file not found. Let's create one.")
		return createConfig()
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// createConfig prompts the user for configuration details and saves them.
func createConfig() (*Config, error) {
	var url, apiKey string

	fmt.Print("Enter Server URL (e.g., http://10.0.0.5): ")
	fmt.Scanln(&url)

	fmt.Print("Enter API Key: ")
	fmt.Scanln(&apiKey)

	config := &Config{
		URL:    strings.TrimSpace(url),
		APIKey: strings.TrimSpace(apiKey),
	}

	if err := saveConfig(config); err != nil {
		return nil, err
	}

	fmt.Printf("Configuration saved to %s\n", configFile)
	return config, nil
}

// saveConfig saves the configuration to the file.
func saveConfig(config *Config) error {
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	return os.WriteFile(configFile, data, 0600)
}

// =================================================================================
// 2. API Client
// =================================================================================

// APIClient is a client for interacting with the cracker API.
type APIClient struct {
	client *http.Client
	config *Config
}

// NewAPIClient creates a new API client.
func NewAPIClient(config *Config) *APIClient {
	return &APIClient{
		client: &http.Client{Timeout: 30 * time.Second},
		config: config,
	}
}

// APIResponse defines the standard success/error response from the API.
type APIResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Details string `json:"details"`
}

// apiRequest is a helper function to make requests to the API.
func (c *APIClient) apiRequest(method, endpoint string, body io.Reader) (*http.Response, error) {
	url := fmt.Sprintf("%s/api/v1%s", c.config.URL, endpoint)
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CrackerJack-Auth", c.config.APIKey)

	return c.client.Do(req)
}

// --- API Methods ---

type SessionHashcat struct {
	Mode             int     `json:"mode"`
	HashType         string  `json:"hashType"`
	Wordlist         string  `json:"wordlist"`
	Rule             string  `json:"rule"`
	Mask             string  `json:"mask"`
	State            int     `json:"state"`
	StateDescription string  `json:"state_description"`
	Progress         float64 `json:"progress"`
	CrackedPasswords int     `json:"crackedPasswords"`
	AllPasswords     int     `json:"allPasswords"`
}

type Session struct {
	ID       int            `json:"id"`
	Name     string         `json:"name"`
	Username string         `json:"username"`
	Hashcat  SessionHashcat `json:"hashcat"`
}

type NewSessionResponse struct {
	ID int `json:"id"`
}

func (c *APIClient) CreateSession(name string) (int, error) {
	payload := map[string]string{"name": name}
	body, _ := json.Marshal(payload)
	resp, err := c.apiRequest("POST", "/sessions", bytes.NewBuffer(body))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("API error: %s", resp.Status)
	}

	var sessionResp NewSessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&sessionResp); err != nil {
		return 0, err
	}
	return sessionResp.ID, nil
}

func (c *APIClient) GetAllSessions() ([]Session, error) {
	resp, err := c.apiRequest("GET", "/sessions", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error getting sessions: %s", resp.Status)
	}
	var sessions []Session
	if err := json.NewDecoder(resp.Body).Decode(&sessions); err != nil {
		return nil, err
	}
	return sessions, nil
}

func (c *APIClient) GetSession(id int) (*Session, error) {
	endpoint := fmt.Sprintf("/sessions/%d", id)
	resp, err := c.apiRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error getting session %d: %s", id, resp.Status)
	}
	var session Session
	if err := json.NewDecoder(resp.Body).Decode(&session); err != nil {
		return nil, err
	}
	return &session, nil
}

func (c *APIClient) UploadHashes(sessionID int, hashes string) error {
	payload := map[string]interface{}{"data": hashes, "contains_usernames": false}
	body, _ := json.Marshal(payload)
	endpoint := fmt.Sprintf("/hashes/%d/upload", sessionID)
	resp, err := c.apiRequest("POST", endpoint, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API error on hash upload: %s", resp.Status)
	}
	return nil
}

func (c *APIClient) SetHashType(sessionID int, hashType string) error {
	payload := map[string]string{"type": hashType}
	body, _ := json.Marshal(payload)
	endpoint := fmt.Sprintf("/hashcat/%d/type", sessionID)
	resp, err := c.apiRequest("POST", endpoint, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API error on set hash type: %s", resp.Status)
	}
	return nil
}

func (c *APIClient) SetMode(sessionID int, mode string) error {
	payload := map[string]string{"mode": mode}
	body, _ := json.Marshal(payload)
	endpoint := fmt.Sprintf("/hashcat/%d/mode", sessionID)
	resp, err := c.apiRequest("POST", endpoint, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API error on set mode: %s", resp.Status)
	}
	return nil
}

func (c *APIClient) SetWordlist(sessionID int, wordlist string) error {
	payload := map[string]string{"name": wordlist}
	body, _ := json.Marshal(payload)
	endpoint := fmt.Sprintf("/wordlists/%d/global", sessionID)
	resp, err := c.apiRequest("POST", endpoint, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API error on set wordlist: %s", resp.Status)
	}
	return nil
}

func (c *APIClient) SetRule(sessionID int, rule string) error {
	payload := map[string]string{"name": rule}
	body, _ := json.Marshal(payload)
	endpoint := fmt.Sprintf("/rules/%d", sessionID)
	resp, err := c.apiRequest("POST", endpoint, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API error on set rule: %s", resp.Status)
	}
	return nil
}

func (c *APIClient) SetMask(sessionID int, mask string) error {
	payload := map[string]string{"mask": mask}
	body, _ := json.Marshal(payload)
	endpoint := fmt.Sprintf("/mask/%d", sessionID)
	resp, err := c.apiRequest("POST", endpoint, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API error on set mask: %s", resp.Status)
	}
	return nil
}

func (c *APIClient) StartJob(sessionID int) error {
	payload := map[string]string{"action": "start"}
	body, _ := json.Marshal(payload)
	endpoint := fmt.Sprintf("/sessions/%d/execute", sessionID)
	resp, err := c.apiRequest("POST", endpoint, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API error on start job: %s", resp.Status)
	}
	return nil
}

type SessionState struct {
	State       int     `json:"state"`
	Description string  `json:"description"`
	Progress    float64 `json:"progress"`
}

func (c *APIClient) GetState(sessionID int) (*SessionState, error) {
	endpoint := fmt.Sprintf("/sessions/%d/state", sessionID)
	resp, err := c.apiRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error getting state: %s", resp.Status)
	}
	var state SessionState
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		return nil, err
	}
	return &state, nil
}

func (c *APIClient) DownloadResults(sessionID int) (string, error) {
	payload := map[string]string{"type": "cracked"}
	body, _ := json.Marshal(payload)
	endpoint := fmt.Sprintf("/hashes/%d/download", sessionID)
	resp, err := c.apiRequest("POST", endpoint, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API error downloading results: %s", resp.Status)
	}
	results, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(results), nil
}

type HashType struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

func (c *APIClient) GetHashTypes() ([]HashType, error) {
	resp, err := c.apiRequest("GET", "/hashcat/types", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error getting hash types: %s", resp.Status)
	}
	var types []HashType
	if err := json.NewDecoder(resp.Body).Decode(&types); err != nil {
		return nil, err
	}
	return types, nil
}

type FileInfo struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

func (c *APIClient) GetWordlists() ([]FileInfo, error) {
	resp, err := c.apiRequest("GET", "/wordlists", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error getting wordlists: %s", resp.Status)
	}
	var files []FileInfo
	if err := json.NewDecoder(resp.Body).Decode(&files); err != nil {
		return nil, err
	}
	return files, nil
}

func (c *APIClient) GetRules() ([]FileInfo, error) {
	resp, err := c.apiRequest("GET", "/rules", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error getting rules: %s", resp.Status)
	}
	var files []FileInfo
	if err := json.NewDecoder(resp.Body).Decode(&files); err != nil {
		return nil, err
	}
	return files, nil
}

// =================================================================================
// 3. TUI (Text-based User Interface)
// =================================================================================

// TUIApp holds the state and components for the TUI.
type TUIApp struct {
	app             *tview.Application
	client          *APIClient
	logView         *tview.TextView
	sessionID       int
	isJobRunning    bool
	sessions        []Session
	hashTypeOptions []string
	wordlistOptions []string
	ruleOptions     []string
}

func NewTUIApp(client *APIClient) *TUIApp {
	return &TUIApp{
		app:    tview.NewApplication(),
		client: client,
	}
}

func (t *TUIApp) log(msg string) {
	fmt.Fprintf(t.logView, "[%s] %s\n", time.Now().Format("15:04:05"), msg)
	t.logView.ScrollToEnd()
}

func (t *TUIApp) Run() {
	// --- TUI Components ---
	pages := tview.NewPages()

	t.logView = tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetWordWrap(true).
		SetChangedFunc(func() {
			t.app.Draw()
		})
	t.logView.SetBorder(true).SetTitle("Logs")

	form := tview.NewForm()
	form.SetBorder(true).SetTitle("Job Configuration")

	resultsTable := tview.NewTable().SetBorders(true)
	resultsTable.SetBorder(true).SetTitle("Results")
	resultsTable.SetCell(0, 0, tview.NewTableCell("Hash").SetSelectable(false).SetTextColor(tview.Styles.SecondaryTextColor))
	resultsTable.SetCell(0, 1, tview.NewTableCell("Plaintext").SetSelectable(false).SetTextColor(tview.Styles.SecondaryTextColor))

	progressGauge := tview.NewTextView().SetTextAlign(tview.AlignCenter)
	progressGauge.SetBorder(true).SetTitle("Progress")

	statusTable := tview.NewTable().SetBorders(true).SetSelectable(true, false)
	statusTable.SetBorder(true).SetTitle("Sessions Status")

	// --- Form Fields ---
	sessionDropdown := tview.NewDropDown().SetLabel("Load Session")
	sessionNameInput := tview.NewInputField().SetLabel("Session Name").SetFieldWidth(30)
	hashesInput := tview.NewTextArea().SetLabel("Hashes").SetWordWrap(true)
	hashTypeDropdown := tview.NewDropDown().SetLabel("Hash Type")
	attackModeDropdown := tview.NewDropDown().SetLabel("Attack Mode").SetOptions([]string{"wordlist", "mask"}, nil)
	wordlistDropdown := tview.NewDropDown().SetLabel("Wordlist")
	rulesDropdown := tview.NewDropDown().SetLabel("Rules")
	maskInput := tview.NewInputField().SetLabel("Mask").SetFieldWidth(30)

	// REMOVED auto-detection logic
	// hashesInput.SetChangedFunc(...)

	form.AddFormItem(sessionDropdown).
		AddFormItem(sessionNameInput).
		AddFormItem(hashesInput).
		AddFormItem(hashTypeDropdown).
		AddFormItem(attackModeDropdown).
		AddFormItem(wordlistDropdown).
		AddFormItem(rulesDropdown).
		AddFormItem(maskInput)

	go t.loadInitialData(sessionDropdown, hashTypeDropdown, wordlistDropdown, rulesDropdown, form, resultsTable)

	// REMOVED "Detect Type" button and reordered
	form.AddButton("Start / Update Job", func() {
		t.startJob(form, progressGauge, resultsTable)
	}).AddButton("Refresh Status", func() {
		t.refreshStatus(statusTable)
		pages.SwitchToPage("status")
	}).AddButton("Quit", func() {
		t.app.Stop()
	})

	// --- Main Layouts ---
	mainViewGrid := tview.NewGrid().
		SetRows(0, 3).
		SetColumns(65, 0).
		SetBorders(true)

	rightPanel := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(resultsTable, 0, 1, false).
		AddItem(t.logView, 0, 1, false)

	mainViewGrid.AddItem(form, 0, 0, 1, 1, 0, 0, true)
	mainViewGrid.AddItem(rightPanel, 0, 1, 1, 1, 0, 0, false)
	mainViewGrid.AddItem(progressGauge, 1, 0, 1, 2, 0, 0, false)

	pages.AddPage("main", mainViewGrid, true, true)
	pages.AddPage("status", statusTable, true, false)

	// --- Hotkeys ---
	t.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyCtrlQ:
			t.app.Stop()
			return nil
		case tcell.KeyF2:
			pages.SwitchToPage("main")
			return nil
		case tcell.KeyF3:
			t.refreshStatus(statusTable)
			pages.SwitchToPage("status")
			return nil
		}
		return event
	})

	t.log("Hotkeys enabled: F2 (Main View), F3 (Status View), Ctrl+Q (Quit)")

	if err := t.app.SetRoot(pages, true).EnableMouse(true).Run(); err != nil {
		panic(err)
	}
}

// REMOVED detectHashType function

func (t *TUIApp) refreshStatus(statusTable *tview.Table) {
	t.log("Refreshing session statuses...")
	go func() {
		sessions, err := t.client.GetAllSessions()
		if err != nil {
			t.app.QueueUpdateDraw(func() {
				t.log(fmt.Sprintf("[red]Error refreshing statuses: %v", err))
			})
			return
		}
		t.app.QueueUpdateDraw(func() {
			statusTable.Clear()
			headers := []string{"ID", "Name", "User", "State", "Progress", "Cracked"}
			for i, h := range headers {
				statusTable.SetCell(0, i, tview.NewTableCell(h).SetSelectable(false).SetTextColor(tview.Styles.SecondaryTextColor))
			}
			for i, s := range sessions {
				crackedStr := fmt.Sprintf("%d/%d", s.Hashcat.CrackedPasswords, s.Hashcat.AllPasswords)
				statusTable.SetCell(i+1, 0, tview.NewTableCell(fmt.Sprintf("%d", s.ID)))
				statusTable.SetCell(i+1, 1, tview.NewTableCell(s.Name))
				statusTable.SetCell(i+1, 2, tview.NewTableCell(s.Username))
				statusTable.SetCell(i+1, 3, tview.NewTableCell(s.Hashcat.StateDescription))
				statusTable.SetCell(i+1, 4, tview.NewTableCell(fmt.Sprintf("%.2f%%", s.Hashcat.Progress)))
				statusTable.SetCell(i+1, 5, tview.NewTableCell(crackedStr))
			}
			t.log("[green]Session statuses refreshed.")
		})
	}()
}

func (t *TUIApp) loadInitialData(sessionDD, hashTypeDD, wordlistDD, rulesDD *tview.DropDown, form *tview.Form, resultsTable *tview.Table) {
	t.log("Fetching options from server...")
	sessions, err := t.client.GetAllSessions()
	if err != nil {
		t.log(fmt.Sprintf("[red]Error fetching sessions: %v", err))
	} else {
		t.sessions = sessions
	}

	hashTypes, _ := t.client.GetHashTypes()
	wordlists, _ := t.client.GetWordlists()
	rules, _ := t.client.GetRules()

	t.app.QueueUpdateDraw(func() {
		sessionOptions := []string{"New Session"}
		for _, s := range t.sessions {
			sessionOptions = append(sessionOptions, fmt.Sprintf("%s (ID: %d)", s.Name, s.ID))
		}
		sessionDD.SetOptions(sessionOptions, func(text string, index int) {
			if index == 0 {
				t.sessionID = 0
				form.GetFormItemByLabel("Session Name").(*tview.InputField).SetText("")
				t.displayResults(resultsTable, "")
				t.log("Switched to new session mode.")
			} else {
				session := t.sessions[index-1]
				t.sessionID = session.ID
				t.log(fmt.Sprintf("Loading data for session %d...", t.sessionID))
				go t.populateFormForSession(t.sessionID, form, hashTypeDD, wordlistDD, rulesDD, resultsTable)
			}
		})

		t.hashTypeOptions = []string{}
		for _, ht := range hashTypes {
			t.hashTypeOptions = append(t.hashTypeOptions, fmt.Sprintf("%s (%s)", ht.Name, ht.Type))
		}
		hashTypeDD.SetOptions(t.hashTypeOptions, nil)

		t.wordlistOptions = []string{}
		for _, wl := range wordlists {
			t.wordlistOptions = append(t.wordlistOptions, wl.Name)
		}
		wordlistDD.SetOptions(t.wordlistOptions, nil)

		t.ruleOptions = []string{"None"}
		for _, r := range rules {
			t.ruleOptions = append(t.ruleOptions, r.Name)
		}
		rulesDD.SetOptions(t.ruleOptions, nil)
		t.log("[green]Options fetched successfully.")
	})
}

func (t *TUIApp) populateFormForSession(id int, form *tview.Form, hashTypeDD, wordlistDD, rulesDD *tview.DropDown, resultsTable *tview.Table) {
	sessionDetails, err := t.client.GetSession(id)
	if err != nil {
		t.log(fmt.Sprintf("[red]Error fetching details for session %d: %v", id, err))
		return
	}
	resultsStr, _ := t.client.DownloadResults(id)

	t.app.QueueUpdateDraw(func() {
		form.GetFormItemByLabel("Session Name").(*tview.InputField).SetText(sessionDetails.Name)

		for i, opt := range t.hashTypeOptions {
			if strings.Contains(opt, fmt.Sprintf("(%s)", sessionDetails.Hashcat.HashType)) {
				hashTypeDD.SetCurrentOption(i)
				break
			}
		}

		if sessionDetails.Hashcat.Mode == 0 { // Wordlist
			form.GetFormItemByLabel("Attack Mode").(*tview.DropDown).SetCurrentOption(0)
			for i, opt := range t.wordlistOptions {
				if opt == sessionDetails.Hashcat.Wordlist {
					wordlistDD.SetCurrentOption(i)
					break
				}
			}
			ruleSet := false
			for i, opt := range t.ruleOptions {
				if opt == sessionDetails.Hashcat.Rule {
					rulesDD.SetCurrentOption(i)
					ruleSet = true
					break
				}
			}
			if !ruleSet {
				rulesDD.SetCurrentOption(0) // "None"
			}
		} else if sessionDetails.Hashcat.Mode == 3 { // Mask
			form.GetFormItemByLabel("Attack Mode").(*tview.DropDown).SetCurrentOption(1)
			form.GetFormItemByLabel("Mask").(*tview.InputField).SetText(sessionDetails.Hashcat.Mask)
		}

		t.displayResults(resultsTable, resultsStr)
		t.log(fmt.Sprintf("[green]Successfully populated form with data from session %d.", id))
	})
}

// startJob is the main TUI logic for starting and monitoring a job.
func (t *TUIApp) startJob(form *tview.Form, progress *tview.TextView, results *tview.Table) {
	if t.isJobRunning {
		t.log("[yellow]A job is already running.")
		return
	}
	t.isJobRunning = true
	t.log("[yellow]Starting/Updating job...")

	var err error
	if t.sessionID == 0 {
		sessionName := form.GetFormItemByLabel("Session Name").(*tview.InputField).GetText()
		t.sessionID, err = t.client.CreateSession(sessionName)
		if err != nil {
			t.log(fmt.Sprintf("[red]Error creating session: %v", err))
			t.isJobRunning = false
			return
		}
		t.log(fmt.Sprintf("[green]New session created with ID: %d", t.sessionID))
	} else {
		t.log(fmt.Sprintf("Updating existing session with ID: %d", t.sessionID))
	}

	hashes := form.GetFormItemByLabel("Hashes").(*tview.TextArea).GetText()
	if hashes != "" {
		if err := t.client.UploadHashes(t.sessionID, hashes); err != nil {
			t.log(fmt.Sprintf("[red]Error uploading hashes: %v", err))
			t.isJobRunning = false
			return
		}
		t.log("Hashes uploaded.")
	} else {
		t.log("No new hashes provided, keeping existing ones.")
	}

	_, hashTypeStr := form.GetFormItemByLabel("Hash Type").(*tview.DropDown).GetCurrentOption()
	htParts := strings.Split(strings.TrimSuffix(hashTypeStr, ")"), " (")
	if len(htParts) < 2 {
		t.log(fmt.Sprintf("[red]Invalid hash type selected: %s", hashTypeStr))
		t.isJobRunning = false
		return
	}
	hashType := htParts[1]
	if err := t.client.SetHashType(t.sessionID, hashType); err != nil {
		t.log(fmt.Sprintf("[red]Error setting hash type: %v", err))
		t.isJobRunning = false
		return
	}
	t.log("Hash type set.")

	_, attackMode := form.GetFormItemByLabel("Attack Mode").(*tview.DropDown).GetCurrentOption()
	if err := t.client.SetMode(t.sessionID, attackMode); err != nil {
		t.log(fmt.Sprintf("[red]Error setting mode: %v", err))
		t.isJobRunning = false
		return
	}
	t.log(fmt.Sprintf("Mode set to %s.", attackMode))

	if attackMode == "wordlist" {
		_, wordlist := form.GetFormItemByLabel("Wordlist").(*tview.DropDown).GetCurrentOption()
		if err := t.client.SetWordlist(t.sessionID, wordlist); err != nil {
			t.log(fmt.Sprintf("[red]Error setting wordlist: %v", err))
			t.isJobRunning = false
			return
		}
		t.log("Wordlist set.")

		_, rule := form.GetFormItemByLabel("Rules").(*tview.DropDown).GetCurrentOption()
		if rule != "None" {
			if err := t.client.SetRule(t.sessionID, rule); err != nil {
				t.log(fmt.Sprintf("[red]Error setting rule: %v", err))
				t.isJobRunning = false
				return
			}
			t.log("Rule set.")
		}
	} else { // mask
		mask := form.GetFormItemByLabel("Mask").(*tview.InputField).GetText()
		if err := t.client.SetMask(t.sessionID, mask); err != nil {
			t.log(fmt.Sprintf("[red]Error setting mask: %v", err))
			t.isJobRunning = false
			return
		}
		t.log("Mask set.")
	}

	if err := t.client.StartJob(t.sessionID); err != nil {
		t.log(fmt.Sprintf("[red]Error starting job: %v", err))
		t.isJobRunning = false
		return
	}
	t.log("[green]Job started successfully! Polling for status...")

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if !t.isJobRunning {
				return
			}
			state, err := t.client.GetState(t.sessionID)
			if err != nil {
				t.app.QueueUpdateDraw(func() {
					t.log(fmt.Sprintf("[red]Error polling status: %v", err))
				})
				t.isJobRunning = false
				return
			}

			t.app.QueueUpdateDraw(func() {
				t.log(fmt.Sprintf("Polling: Status='%s', Progress=%.2f%%", state.Description, state.Progress))
				progressText := fmt.Sprintf("%s - %.2f%%", state.Description, state.Progress)
				progress.SetText(progressText)
			})

			if state.State == 2 || state.State == 3 || state.State == 5 {
				t.app.QueueUpdateDraw(func() {
					t.log("[green]Job finished. Fetching results...")
					resultsStr, err := t.client.DownloadResults(t.sessionID)
					if err != nil {
						t.log(fmt.Sprintf("[red]Error fetching results: %v", err))
					} else {
						t.displayResults(results, resultsStr)
					}
					t.isJobRunning = false
				})
				return
			}
		}
	}()
}

func (t *TUIApp) displayResults(table *tview.Table, resultsStr string) {
	table.Clear()
	table.SetCell(0, 0, tview.NewTableCell("Hash").SetSelectable(false).SetTextColor(tview.Styles.SecondaryTextColor))
	table.SetCell(0, 1, tview.NewTableCell("Plaintext").SetSelectable(false).SetTextColor(tview.Styles.SecondaryTextColor))

	lines := strings.Split(resultsStr, "\n")

	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		t.log("No cracked passwords found for this session.")
		return
	}

	rowCount := 1
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}
		table.SetCell(rowCount, 0, tview.NewTableCell(parts[0]).SetTextColor(tview.Styles.PrimaryTextColor))
		table.SetCell(rowCount, 1, tview.NewTableCell(parts[1]).SetTextColor(tview.Styles.TertiaryTextColor))
		rowCount++
	}
	t.log(fmt.Sprintf("Displayed %d results.", rowCount-1))
}

// =================================================================================
// 4. CLI (Command-Line Interface)
// =================================================================================

func runCLI(client *APIClient, args *cliArgs) {
	fmt.Println("Running in CLI mode...")

	fmt.Printf("Creating session '%s'...\n", args.sessionName)
	sessionID, err := client.CreateSession(args.sessionName)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Session created with ID: %d\n", sessionID)

	var hashes string
	if args.hashesFile != "" {
		data, err := os.ReadFile(args.hashesFile)
		if err != nil {
			fmt.Printf("Error reading hashes file: %v\n", err)
			os.Exit(1)
		}
		hashes = string(data)
	} else {
		hashes = args.hashes
	}

	if err := client.UploadHashes(sessionID, hashes); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Hashes uploaded.")

	if err := client.SetHashType(sessionID, args.hashType); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Hash type set.")

	if err := client.SetMode(sessionID, args.mode); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Mode set to %s.\n", args.mode)

	if args.mode == "wordlist" {
		if err := client.SetWordlist(sessionID, args.wordlist); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Wordlist set.")
		if args.rule != "" {
			if err := client.SetRule(sessionID, args.rule); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Rule set.")
		}
	} else { // mask
		if err := client.SetMask(sessionID, args.mask); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Mask set.")
	}

	if err := client.StartJob(sessionID); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Job started! Polling for status...")

	for {
		state, err := client.GetState(sessionID)
		if err != nil {
			fmt.Printf("Error polling status: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\rStatus: %s - %.2f%%", state.Description, state.Progress)

		if state.State == 2 || state.State == 3 || state.State == 5 {
			fmt.Println("\nJob finished.")
			results, err := client.DownloadResults(sessionID)
			if err != nil {
				fmt.Printf("Error fetching results: %v\n", err)
			} else {
				fmt.Println("\n--- Cracked Passwords ---")
				fmt.Println(results)
			}
			break
		}
		time.Sleep(5 * time.Second)
	}
}

// cliArgs holds the parsed command-line flags.
type cliArgs struct {
	interactive bool
	sessionName string
	hashes      string
	hashesFile  string
	hashType    string
	mode        string
	wordlist    string
	rule        string
	mask        string
}

// =================================================================================
// 5. Main Function
// =================================================================================

func main() {
	// --- Flag Definition ---
	args := cliArgs{}
	flag.BoolVar(&args.interactive, "i", false, "Run in interactive TUI mode.")
	flag.StringVar(&args.sessionName, "session-name", "CLI Job", "Name for the cracking session.")
	flag.StringVar(&args.hashes, "hashes", "", "String of hashes, separated by newlines.")
	flag.StringVar(&args.hashesFile, "hashes-file", "", "Path to a file containing hashes.")
	flag.StringVar(&args.hashType, "hash-type", "", "Hashcat mode number (e.g., 0 for MD5).")
	flag.StringVar(&args.mode, "mode", "wordlist", "Attack mode ('wordlist' or 'mask').")
	flag.StringVar(&args.wordlist, "wordlist", "", "Wordlist file to use (for wordlist mode).")
	flag.StringVar(&args.rule, "rule", "", "Rules file to use (optional, for wordlist mode).")
	flag.StringVar(&args.mask, "mask", "", "Mask to use (for mask mode).")
	flag.Parse()

	// --- Load Config and Initialize Client ---
	config, err := loadConfig()
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		os.Exit(1)
	}
	client := NewAPIClient(config)

	// --- Run Mode ---
	if args.interactive {
		tui := NewTUIApp(client)
		tui.Run()
	} else {
		// Basic validation for CLI mode
		if args.hashes == "" && args.hashesFile == "" {
			fmt.Println("Error: Must provide hashes via -hashes or -hashes-file flag for CLI mode.")
			flag.Usage()
			os.Exit(1)
		}
		if args.hashType == "" {
			fmt.Println("Error: Must provide -hash-type for CLI mode.")
			flag.Usage()
			os.Exit(1)
		}
		if args.mode == "wordlist" && args.wordlist == "" {
			fmt.Println("Error: Must provide -wordlist for wordlist mode.")
			flag.Usage()
			os.Exit(1)
		}
		if args.mode == "mask" && args.mask == "" {
			fmt.Println("Error: Must provide -mask for mask mode.")
			flag.Usage()
			os.Exit(1)
		}
		runCLI(client, &args)
	}
}
