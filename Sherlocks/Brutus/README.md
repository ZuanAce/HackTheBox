# Brutus

## Challenge Description
> ![image](https://github.com/user-attachments/assets/88a12cf9-2c4f-402a-ab06-0dcc5815db97)
> 
> **Scenario**<br>
> In this very easy Sherlock, you will familiarize yourself with Unix auth.log and wtmp logs. We'll explore a scenario where a Confluence server was brute-forced via its SSH service. After gaining access to the server, the attacker performed additional activities, which we can track using auth.log. Although auth.log is primarily used for brute-force analysis, we will delve into the full potential of this artifact in our investigation, including aspects of privilege escalation, persistence, and even some visibility into command execution.

----

## Initial Analysis
### auth.log
The `auth.log` file is primarily used for tracking authentication mechanisms. Whenever a user
attempts to log in, switch users, or perform any task that requires authentication, an entry is made
in this log file. This includes activities involving sshd (SSH daemon), sudo actions, and cron jobs
requiring authentication. Typical fields included are **Date and Time**, **Hostname**, **Service**, **PID**, **User**,
**Authentication Status**, **Remote IP Address/Hostname**, and **Message**.

### WTMP
The WTMP file logs all login and logout events on the system. It's a binary file, typically located at
`/var/log/wtmp` . The last command can be used to read this file, providing a history of user
logins and logouts, system reboots, and runlevel changes. Since WTMP is a binary file, it's not directly readable like `auth.log` . However, when viewed through utilities like `last` , the following information such as **Username**, **Terminal**, **IP Address/Hostname**, **Login Time**, **Logout Time**, and **Duration**. `utmpdump` allows us to read the `wtmp` file provided as well. The `utmpdump` tool is a utility in Linux and Unix-like systems that is used to read and decode
binary files such as `utmp` , `wtmp` , and `btmp`.

> [!TIP]
> Commands to be noted
> - When the output is not long: `utmpdump /var/log/wtmp`
> - When the output is too long: `utmpdump /var/log/wtmp > output.txt`
> - List only the programs in the log: `awk '{print $5}' auth.log | sed 's/[\[\:].*//g' | sort|uniq -c|sort -n > log_programs.txt`
> - Timezone conversion: `TZ=UTC last -f wtmp`
> - pam_unix not giving any useful info: `grep sshd auth.log |grep -v pam_unix`

----

## Questions
### Question 1: Analyzing the auth.log, can you identify the IP address used by the attacker to carry out a brute force attack?
> [!TIP]
> Hint: Searching for keywords associated with brute force attempts may help in identifying potential attacks. Keywords such as `Failed password`, `Invalid user`, `authentication failure`, `sshd`, `PAM`, `Too many authentication failures`, `Connection closed by`, `password mismatch`, and `user not found` are commonly found in auth.log files during brute force attempts. Monitoring these keywords, especially when repeated from the same IP address or targeting the same username, can be an effective way to detect and mitigate potential brute force attacks.

Using the command `grep sshd auth.log` allows you to extract all log entries containing the string `sshd`.

![image](https://github.com/user-attachments/assets/0e86acb3-4835-4bcb-b0fc-db4934a011be)

In the provided log excerpt, repeated authentication attempts from a single IP address, `65.2.161.68`, strongly suggest a brute force attack. Notably, these attempts occur within mere seconds, targeting multiple user accounts such as `admin`, `backup`, `server_adm`, `root`, and `svc_account`.

**Answer**: 65.2.161.68

### Question 2: The brute force attempts were successful, and the attacker gained access to an account on the server. What is the username of this account?
> [!TIP]
> Hint: Look for keywords indicating successful login attempts to identify the compromised account. Common phrases include `Accepted password` or `Accepted publickey`, often followed by the username and IP address of the login source. Additionally, phrases like `session opened` may confirm that a session was successfully initiated. Cross-referencing these entries with the timestamps of failed login attempts can help pinpoint the exact moment of compromise and identify the account targeted during a brute force attack.

Using the command `grep "Accepted password" auth.log`, we identified multiple successful login attempts from various accounts and IPs. Specifically, the account `root` was accessed from `203.101.190.9` and `65.2.161.68`, while the account `cyberjunkie` was accessed from `65.2.161.68`. Notably, in our earlier analysis, we discovered brute force attempts targeting the `root` account from the same IP, `65.2.161.68`. This correlation strongly suggests that the compromised account is `root`.

![image](https://github.com/user-attachments/assets/6226b732-cf36-44ea-ba3c-69256fe8318a)

**Answer**: root

### Question 3: Can you identify the timestamp when the attacker manually logged in to the server to carry out their objectives?
> [!TIP]
> Hint: It's important to note that the first successful login by the attacker was the result of an automated brute force attempt, and the session was closed within the same second it was established. After obtaining the working credentials, the attacker manually logged in, and we need to identify that login. Use the `wtmp` artifact to view the login time of the working session and correlate that with `auth.log`.

Using the command `grep sshd auth.log | grep 65.2.161.68 | grep -A3 "Accepted password"`, we can observe the following entries:

![image](https://github.com/user-attachments/assets/35930b42-8b44-4ce1-8a39-8cc46de0cfc9)

From the logs, the first successful login occurred at `Mar 6 06:31:40`, but the session was immediately disconnected, indicating an automated brute force process. The second login at `Mar 6 06:32:44` lasted until `Mar 6 06:37:24`, suggesting a manual login.

To confirm this, the `wtmp` artifact can be analyzed using the command `utmpdump wtmp | grep 65.2.161.68`. This will reveal the login time of the working session associated with the IP `65.2.161.68`, which can then be correlated with the `auth.log` timestamps to verify the manual login activity. 

![image](https://github.com/user-attachments/assets/57aa2b1a-71ee-4141-9022-9d262ce4a296)

The wtmp artifact captures the start of the actual working session, making `06:32:45` the correct answer when identifying the moment the attacker began interacting with the server.

> [!NOTE]
> - In auth.log: The time `06:32:44` represents when the SSH daemon (sshd) accepted the password for the login. This log reflects the exact moment the authentication succeeded.
> - In wtmp: The time `06:32:45` corresponds to when the session was fully established and logged by the system. This includes any processing time between accepting the password and opening the terminal session (e.g., initializing the user environment or allocating a pseudo-terminal).

**Answer**: 2024-03-06 06:32:45

### Question 4: SSH login sessions are tracked and assigned a session number upon login. What is the session number assigned to the attacker's session for the user account from Question 2?
> [!TIP]
> Hint : Session number is assigned immediately after the password is accepted.

Using the command `grep session auth.log` reveals logs containing strings `session`.

![image](https://github.com/user-attachments/assets/2abc6e3a-b1a9-4d71-8c05-5bc77d10ba2a)

From the logs, it can be observed that session information containing the session number is logged under `systemd-logind`. To narrow the results, we used `grep systemd-logind auth.log`, revealing the following entries:

![image](https://github.com/user-attachments/assets/39cca933-1ac5-48cc-a9d3-9f798753d349)

From these logs:
- At `06:31:40`, session 34 was created for the root user but was removed immediately. This aligns with the earlier observation of an automated brute force login that disconnected within the same second.
- At `06:32:44`, session 37 was created for the root user and lasted until `06:37:24`, corresponding to the manual login we previously identified.

Thus, the session number assigned to the attacker's manual login is 37. 

**Answer**: 37

### Question 5: The attacker added a new user as part of their persistence strategy on the server and gave this new user account higher privileges. What is the name of this account?
> [!TIP]
> Hint: The auth.log file tracks user and group modifications on the server. Look for keywords such as `useradd`, `usermod`, `groupadd`, and `sudo` to identify user additions and privilege escalations.

Using the command grep useradd auth.log, we identified the creation of a new user account:
```bash
Mar  6 06:34:18 ip-172-31-35-28 useradd[2592]: new user: name=cyberjunkie, UID=1002, GID=1002, home=/home/cyberjunkie, shell=/bin/bash, from=/dev/pts/1
```
This shows that a new user named cyberjunkie was added to the system at `06:34:18`. Adding a new user is an effective way of maintaining persistence and can be completed without bringing in any additional tooling and essentially 'living off the land'

Next, using the command grep usermod auth.log, we found the following entries:
```bash
Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to group 'sudo'
Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to shadow group 'sudo'
```
These logs indicate that the user cyberjunkie was added to the sudo group and its shadow group, granting it elevated privileges on the server.

**Answer**: cyberjunkie

### Question 6: What is the MITRE ATT&CK sub-technique ID used for persistence by creating a new account?
> [!TIP]
> If you have found the answer to Question 5, consult the MITRE ATT&CK enterprise matrix to determine the sub-technique ID under the persistence tactic.
   
The attacker created a new local user account (cyberjunkie) on the compromised host as part of their persistence strategy. According to the MITRE ATT&CK framework, this activity falls under T1136: Create Account, specifically the sub-technique T1136.001: Local Account, which involves creating local accounts to maintain access to a system.

![image](https://github.com/user-attachments/assets/453de1f8-b468-4ab8-b01b-1e7ca441745d)

**Answer**: T1136.001

### Question 7: What time did the attacker's first SSH session end according to auth.log?
From previous analysis, we identified that the attacker's manual login was assigned session number 37. Using the command `grep "session 37" auth.log`, we found the following entries:

```bash        
Mar  6 06:32:44 ip-172-31-35-28 systemd-logind[411]: New session 37 of user root.
Mar  6 06:37:24 ip-172-31-35-28 systemd-logind[411]: Removed session 37.
```

Based on these logs, session 37 was removed at `Mar 6 06:37:24`, indicating that the attacker's first SSH session ended at this time.

**Answer**: 2024-03-06 06:37:24

