package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bramvdbogaerde/go-scp"
	logpkg "go.codycody31.dev/caprover-backup/shared/logger"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
)

type CaproverCredentials struct {
	Password string `json:"password"`
}

type CaproverConfig struct {
	URL      string `yaml:"url"`
	Password string `yaml:"password"`
}

type Volume struct {
	Name string `json:"name"`
}

type ServerSettings struct {
	DisableCaproverBackup bool `yaml:"disableCaproverBackup"` // Disable CapRover backup
	DisableVolumeBackup   bool `yaml:"disableVolumeBackup"`   // Disable volume backup

	// TODO: Ability to define explicit volumes to backup
	// by default we use exclude, but if include is defined, we only backup those volumes
	IncludeVolumes []Volume `yaml:"includeVolumes"` // Volumes to include in backup
	ExcludeVolumes []Volume `yaml:"excludeVolumes"` // Volumes to exclude from backup
}

type Server struct {
	Host     string         `yaml:"host"`
	User     string         `yaml:"user"`
	Password string         `yaml:"password"`
	Caprover CaproverConfig `yaml:"caprover"`
	Settings ServerSettings `yaml:"settings"` // Server specific settings
}

type Ntfy struct {
	URL   string `yaml:"url"`
	Token string `yaml:"token"`
}

type Config struct {
	LogFile    string   `yaml:"logFile"`
	BackupPath string   `yaml:"backupPath"`
	Servers    []Server `yaml:"servers"`
	Ntfy       Ntfy     `yaml:"ntfy"`
}

var logger *logpkg.Logger

func main() {
	// Read YAML configuration
	data, err := ioutil.ReadFile("caprover-backup.yaml")
	if err != nil {
		log.Fatalf("Error reading YAML file: %v", err)
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		log.Fatalf("Error parsing YAML file: %v", err)
	}

	logger, err = logpkg.NewLogger(config.LogFile, 5) // Log file with max size 5MB
	if err != nil {
		log.Fatalf("Error initializing logger: %v", err)
	}

	// Perform system checks, for example if the backup path is writable, or ensure the folder exists
	err = systemChecks(config)
	if err != nil {
		logger.Log(logpkg.ERROR, fmt.Sprintf("System checks failed: %v", err))
	}

	logger.Log(logpkg.WELCOME, "Starting CapRover Backup..")

	var wg sync.WaitGroup

	var failedServers []string

	// Backup CapRover on each server
	for _, server := range config.Servers {
		wg.Add(1)
		go func(s Server) {
			defer wg.Done()
			if s.Settings.DisableCaproverBackup {
				logger.Log(logpkg.INFO, "CapRover backup disabled", logpkg.WithServer(s.Host))
				return
			}

			err := backupCaprover(s, config)
			if err != nil {
				failedServers = append(failedServers, s.Host)
				logger.Log(logpkg.ERROR, fmt.Sprintf("Failed to backup CapRover: %v", err), logpkg.WithServer(s.Host))
				_ = ntfy(config.Ntfy.URL+"cron", config.Ntfy.Token, fmt.Sprintf("CapRover Backup: %s", s.Host), 3, []string{"tada"}, fmt.Sprintf("Backup failed at %s: %s", time.Now().Format("2006/01/02 15:04:05"), err.Error()))
			}
		}(server)
	}

	// Backup CapRover volumes on each server
	for _, server := range config.Servers {
		wg.Add(1)
		go func(s Server) {
			defer wg.Done()
			if s.Settings.DisableVolumeBackup {
				logger.Log(logpkg.INFO, "Volume backup disabled", logpkg.WithServer(s.Host))
				return
			}

			err := backupVolumes(s, config)
			if err != nil {
				failedServers = append(failedServers, s.Host)
				logger.Log(logpkg.ERROR, fmt.Sprintf("Failed to backup volumes: %v", err), logpkg.WithServer(s.Host))
				_ = ntfy(config.Ntfy.URL+"cron", config.Ntfy.Token, fmt.Sprintf("CapRover Volume Backup: %s", s.Host), 3, []string{"tada"}, fmt.Sprintf("Volume backup failed at %s: %s", time.Now().Format("2006/01/02 15:04:05"), err.Error()))
			}
		}(server)
	}

	wg.Wait()
	if len(failedServers) > 0 {
		logger.Log(logpkg.ERROR, fmt.Sprintf("Failed to backup servers: %v", failedServers))
	} else {
		logger.Log(logpkg.SUCCESS, "All backups completed successfully")
	}
}

func backupVolumes(server Server, config Config) error {
	// TODO: Support for private key: https://gist.github.com/stefanprodan/2d20d0c6fdab6f14ce8219464e8b4b9a
	// auto build auth methods based on whats set

	clientConfig := &ssh.ClientConfig{
		User:            server.User,
		Auth:            []ssh.AuthMethod{ssh.Password(server.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", server.Host), clientConfig)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	logger.Log(logpkg.INFO, "Backing up CapRover volumes...", logpkg.WithServer(server.Host))
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}
	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		return fmt.Errorf("failed to request PTY: %v", err)
	}
	w, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdin pipe: %v", err)
	}
	r, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdout pipe: %v", err)
	}
	in, out := muxShell(w, r)
	if err := session.Start("/bin/sh"); err != nil {
		return fmt.Errorf("failed to start shell: %v", err)
	}
	<-out //ignore the shell output

	commands := map[string]string{
		"make backups directory":        "mkdir -p /root/caprover-backups",
		"download volume backup script": "cd /root/caprover-backups && curl -O https://gist.githubusercontent.com/Codycody31/2faf1b21f1e20a7ec0752e2f7b493b05/raw/03a2c99962c9424cc71da8ec14060f31091396df/caprover-volume-backup.sh",
		"allow execution of script":     "cd /root/caprover-backups && chmod +x caprover-volume-backup.sh",
		"volume backup":                 "cd /root/caprover-backups && ./caprover-volume-backup.sh",

		// TODO: Test commands enabled with debug mode, and have production mode with the above commands
		// "make fake backup file":                 "touch captain_volumes_backup.tar.gz",
		// "populate fake backup with random data": "dd if=/dev/urandom of=captain_volumes_backup.tar.gz bs=1M count=6144",
	}

	for name, cmd := range commands {
		logger.Log(logpkg.INFO, fmt.Sprintf("Executing command: %s", name), logpkg.WithServer(server.Host))
		in <- cmd
		<-out
		logger.Log(logpkg.INFO, fmt.Sprintf("Executed command: %s", name), logpkg.WithServer(server.Host))
	}

	logger.Log(logpkg.SUCCESS, "CapRover volumes backed up successfully", logpkg.WithServer(server.Host))

	localFileName := fmt.Sprintf(config.BackupPath+"/volumes-%s-%s.tar.gz", server.Host, time.Now().Format("2006-01-02-15-04-05"))

	logger.Log(logpkg.INFO, "Downloading backup...", logpkg.WithServer(server.Host))
	scpclient, err := scp.NewClientBySSH(conn)
	if err != nil {
		return fmt.Errorf("failed to create new SSH session from existing connection: %v", err)
	}
	defer scpclient.Close()
	f, _ := os.Create(localFileName)
	defer f.Close()
	err = scpclient.CopyFromRemote(context.Background(), f, "/root/caprover-backups/captain_volumes_backup.tar.gz")
	if err != nil {
		return fmt.Errorf("failed to download backup: %v", err)
	}
	logger.Log(logpkg.SUCCESS, fmt.Sprintf("Backup downloaded successfully (%s)", byteCountSI(0)), logpkg.WithServer(server.Host))

	logger.Log(logpkg.INFO, "Cleaning up remote server...", logpkg.WithServer(server.Host))
	in <- "rm -rf /root/caprover-backups"
	in <- "exit"
	session.Wait()
	logger.Log(logpkg.SUCCESS, "Server cleaned up successfully", logpkg.WithServer(server.Host))

	fileInfo, err := os.Stat(localFileName)
	if err != nil {
		return fmt.Errorf("failed to get file size: %v", err)
	}

	logger.Log(logpkg.SUCCESS, fmt.Sprintf("CapRover volumes backed up successfully to %s (%s)", localFileName, byteCountSI(fileInfo.Size())), logpkg.WithServer(server.Host))

	err = ntfy(config.Ntfy.URL+"cron", config.Ntfy.Token, fmt.Sprintf("CapRover Volume Backup: %s", server.Host), 3, []string{"tada"}, fmt.Sprintf("CapRover volumes backed up successfully at %s, backup size: %s", time.Now().Format("2006/01/02 15:04:05"), byteCountSI(fileInfo.Size())))
	if err != nil {
		return fmt.Errorf("failed to send ntfy.sh notification: %s", err.Error())
	}

	return nil
}

func backupCaprover(server Server, config Config) error {
	logger.Log(logpkg.INFO, "Backing up CapRover...", logpkg.WithServer(server.Host))

	logger.Log(logpkg.INFO, "Obtaining API Token...", logpkg.WithServer(server.Host))
	caproverApiToken, err := getApiToken(server.Caprover.URL, server.Caprover.Password)
	if err != nil {
		return fmt.Errorf("failed to obtain API Token: %v", err)
	}
	logger.Log(logpkg.SUCCESS, "API Token obtained successfully", logpkg.WithServer(server.Host))

	logger.Log(logpkg.INFO, "Creating backup...", logpkg.WithServer(server.Host))
	downloadToken, err := createBackup(server.Caprover.URL, caproverApiToken)
	if err != nil {
		return fmt.Errorf("failed to create backup: %v", err)
	}
	logger.Log(logpkg.SUCCESS, "Backup created successfully", logpkg.WithServer(server.Host))

	// generate random name for backup file
	backupFileName := fmt.Sprintf("%s/backup-%s-%s.tar", config.BackupPath, server.Host, time.Now().Format("2006-01-02-15-04-05"))

	logger.Log(logpkg.INFO, "Downloading backup...", logpkg.WithServer(server.Host))
	err = downloadFile(backupFileName, fmt.Sprintf("%s/api/v2/downloads/?namespace=captain&downloadToken=%s", server.Caprover.URL, downloadToken))
	if err != nil {
		return fmt.Errorf("failed to download backup: %v", err)
	}

	backupFileInfo, err := os.Stat(backupFileName)
	if err != nil {
		return fmt.Errorf("failed to get file size for backup.tar: %v", err)
	}

	logger.Log(logpkg.SUCCESS, fmt.Sprintf("Backup downloaded successfully  (%s)", byteCountSI(backupFileInfo.Size())), logpkg.WithServer(server.Host))

	err = ntfy(config.Ntfy.URL+"cron", config.Ntfy.Token, fmt.Sprintf("CapRover Backup: %s", server.Host), 3, []string{"tada"}, fmt.Sprintf("Backup completed successfully at %s, backup size: %s", time.Now().Format("2006/01/02 15:04:05"), byteCountSI(backupFileInfo.Size())))
	if err != nil {
		return fmt.Errorf("failed to send ntfy.sh notification: %s", err.Error())
	}

	return nil
}

func getApiToken(url, password string) (string, error) {
	// Create JSON request body
	creds := CaproverCredentials{Password: password}
	requestBody, err := json.Marshal(creds)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %v", err)
	}

	// Create POST request
	req, err := http.NewRequest("POST", url+"/api/v2/login", bytes.NewBuffer(requestBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	req.Header.Set("x-namespace", "captain")

	// Perform POST request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to perform POST request: %v", err)
	}
	defer resp.Body.Close()

	// Check if request was successful
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	// Parse JSON response
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to unmarshal JSON response: %v", err)
	}

	// Extract token from response
	if token, ok := result["data"].(map[string]interface{})["token"].(string); ok {
		return token, nil
	}

	return "", fmt.Errorf("token not found in response")
}

func createBackup(url, token string) (string, error) {
	// Create POST request
	req, err := http.NewRequest("POST", url+"/api/v2/user/system/createbackup", bytes.NewBuffer([]byte("{\"postDownloadFileName\":\"backup.tar\"}")))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("x-namespace", "captain")
	req.Header.Set("x-captain-auth", token)

	// Perform POST request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to perform POST request: %v", err)
	}
	defer resp.Body.Close()

	// Check if request was successful
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	// Parse JSON response
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to unmarshal JSON response: %v", err)
	}

	// Extract download token from response
	if downloadToken, ok := result["data"].(map[string]interface{})["downloadToken"].(string); ok {
		return downloadToken, nil
	}

	return "", fmt.Errorf("download token not found in response")
}

func downloadFile(filepath string, url string) (err error) {

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check server response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	// Writer the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

func moveFile(sourcePath, destPath string) error {
	inputFile, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("Couldn't open source file: %v", err)
	}
	defer inputFile.Close()

	outputFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("Couldn't open dest file: %v", err)
	}
	defer outputFile.Close()

	_, err = io.Copy(outputFile, inputFile)
	if err != nil {
		return fmt.Errorf("Couldn't copy to dest from source: %v", err)
	}

	inputFile.Close() // for Windows, close before trying to remove: https://stackoverflow.com/a/64943554/246801

	err = os.Remove(sourcePath)
	if err != nil {
		return fmt.Errorf("Couldn't remove source file: %v", err)
	}
	return nil
}

func ntfy(endpoint string, auth string, title string, priority int, tags []string, content string) error {
	// Generated by curl-to-Go: https://mholt.github.io/curl-to-go

	//     curl \
	//         -H "Authorization: Bearer auth" \
	//         -H "Title: title" \
	//         -H "Priority: priority" \
	//         -H "Tags: tags" \
	//         -d "content" \
	//     endpoint

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(content))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth))
	req.Header.Set("Title", title)
	req.Header.Set("Priority", fmt.Sprint(priority))
	req.Header.Set("Tags", strings.Join(tags, ","))
	req.Header.Set("Content-Type", "text/plain")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("non-2xx status code: %d - %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

func byteCountSI(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}

// source: https://stackoverflow.com/a/24441190/17473352
func muxShell(w io.Writer, r io.Reader) (chan<- string, <-chan string) {
	in := make(chan string, 1)
	out := make(chan string, 1)
	var wg sync.WaitGroup
	wg.Add(1) //for the shell itself
	go func() {
		for cmd := range in {
			wg.Add(1)
			w.Write([]byte(cmd + "\n"))
			wg.Wait()
		}
	}()
	go func() {
		var (
			buf [65 * 1024]byte
			t   int
		)
		for {
			n, err := r.Read(buf[t:])
			if err != nil {
				close(in)
				close(out)
				return
			}
			t += n
			if buf[t-2] == '#' { //assuming the $PS1 == 'sh-4.3$ '
				out <- string(buf[:t])
				t = 0
				wg.Done()
			}
		}
	}()
	return in, out
}

func systemChecks(config Config) error {
	// Create backup directory if it doesn't exist
	if _, err := os.Stat(config.BackupPath); os.IsNotExist(err) {
		err = os.Mkdir(config.BackupPath, 0755)
		if err != nil {
			return fmt.Errorf("failed to create backup directory: %v", err)
		}
		logger.Log(logpkg.INFO, fmt.Sprintf("Created backup directory %s", config.BackupPath))
	}

	return nil
}
