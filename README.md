# CapRover Backup Utility

This Go application performs automated backups of CapRover applications and volumes from multiple servers. It uses SSH and SCP for volume backups and CapRover's API for application backups. Notifications are sent using `ntfy.sh`.

## Features

- Back up CapRover applications and volumes from multiple servers concurrently.
- Configurable through a YAML file.
- Logs activities and errors to a specified log file.
- Sends notifications using `ntfy.sh`.
- Customizable backup settings per server.

## Requirements

- Go 1.15 or higher
- CapRover server(s) with API access
- SSH access to the server(s)

## Configuration

The configuration is defined in a `caprover-backup.yaml` file. Here's a sample configuration:

```yaml
logFile: "/path/to/logfile.log"
backupPath: "/path/to/backup"
servers:
  - host: "server1.example.com"
    user: "username"
    password: "password"
    caprover:
      url: "https://captain.server1.example.com"
      password: "caprover_password"
    settings:
      disableCaproverBackup: false
      disableVolumeBackup: false
      includeVolumes:
        - name: "volume1"
      excludeVolumes:
        - name: "volume2"
  - host: "server2.example.com"
    user: "username"
    password: "password"
    caprover:
      url: "https://captain.server2.example.com"
      password: "caprover_password"
    settings:
      disableCaproverBackup: false
      disableVolumeBackup: false
ntfy:
  url: "https://ntfy.sh/your-endpoint"
  token: "your-ntfy-token"
```

### Configuration Fields

- `logFile`: Path to the log file.
- `backupPath`: Directory where backups will be stored.
- `servers`: List of servers to back up.
  - `host`: Hostname or IP address of the server.
  - `user`: SSH username.
  - `password`: SSH password.
  - `caprover`: CapRover configuration.
    - `url`: CapRover URL.
    - `password`: CapRover password.
  - `settings`: Backup settings for the server.
    - `disableCaproverBackup`: Disable CapRover application backup.
    - `disableVolumeBackup`: Disable volume backup.
    - `includeVolumes`: List of volumes to include in the backup.
    - `excludeVolumes`: List of volumes to exclude from the backup.
- `ntfy`: `ntfy.sh` configuration.
  - `url`: `ntfy.sh` endpoint URL.
  - `token`: `ntfy.sh` token.

## Usage

1. **Install Dependencies**: Ensure you have Go installed.

2. **Clone the Repository**: Clone this repository to your local machine.

3. **Configure**: Create a `caprover-backup.yaml` file in the root of the project and fill in the necessary details.

4. **Build**: Build the application using the following command:

   ```bash
   go build -o caprover-backup
   ```

5. **Run**: Execute the built application:

   ```bash
   ./caprover-backup
   ```

## Logging

Logs are written to the specified log file. Each log entry includes a timestamp and log level (INFO, ERROR, etc.).

## Notifications

Notifications are sent using `ntfy.sh`. Ensure your `ntfy.sh` endpoint and token are correctly configured in the YAML file.

## Error Handling

Errors are logged and, where possible, include detailed information to aid in troubleshooting.

## Future Improvements

- Support for private key authentication.
- More granular volume inclusion/exclusion logic.
- Enhanced error handling and retry mechanisms.

## Contributing

Feel free to submit issues, fork the repository, and send pull requests. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the MIT License.

## Contact

For questions or support, please open an issue in the GitHub repository.