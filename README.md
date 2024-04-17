# RDS Watcher Proof of Concept

**RDS Watcher** is a proof of concept designed to monitor Windows security events, specifically targeting event ID 4625 (failed login attempts). It dynamically updates firewall rules to block IP addresses or subnets after repeated failures.

## Features

- **Dynamic Firewall Rule Management**: Automatically adds firewall rules to block IP addresses and subnets based on failed login attempts.
- **Customizable Settings**: Users can specify settings such as the duration for rules to expire and the limit on failed attempts via command-line arguments.
- **Logging**: Provides detailed logging of all monitored events and actions taken.

## Command-Line Arguments

RDS Watcher supports several command-line arguments to customize its behavior:

- **/age [hours]**: Sets the length in hours for firewall rules to age out. Default is 24 hours. Set to 0 for never expiring.
- **/limit [number]**: Sets the number of failed login attempts before a firewall rule is added. Default is 30.
- **/24 [number]**: Activates subnet monitoring and sets the limit for subnet blocking. Default is 100.
- **/debug**: Enables debug mode, which increases the verbosity of the logs.
- **/logpath [path]**: Specifies the path to save the log file. If not set, logging will be printed to the console.

```bash
RDSWatcherPOC.exe /age 24 /limit 30 /24 50 /logpath "C:\\Logs\\RDSWatcher.log"
```

## Future Enhancements
- **Allow Lists**: Implementing allow lists to exclude certain IPs or ranges from being blocked, ensuring safe or internal IPs are not affected.
- **Permanent Blocks**: Adding the option to permanently block IPs or subnets based on specific criteria or repeated offenses.
- **Windows Service**: Development of a Windows service version for better integration with Windows Server environments.
- **GUI Editor**: A graphical user interface to allow non-technical users to configure settings and view logs and statistics more conveniently.


![image](https://raw.githubusercontent.com/linuxx/RDSWatcher/master/img/ss.png)


