# Hi! This is my personal firewall script that I created to experiment with networking and security! 

The main functionality of the script is to send a message to IPs that are scanning the server, and after a certain suspicious number of scans, to block that IP.
By blocking, I mean their SYN packets will be dropped.
Also queries a database of known IPs and analyzes the threat level of each IP - blocking instantly if marked as malicious (AbuseIPDB)


Efficacy:

Before
<img width="423" height="21" alt="image" src="https://github.com/user-attachments/assets/3e022f6f-80f1-4134-92c2-d577a1a0c0fc" />

After
<img width="450" height="15" alt="image" src="https://github.com/user-attachments/assets/81822082-a6b5-4524-aebc-cedcba04343c" />

HOW TO USE:
Create the firewall file in your Linux directory
Copy the Python code into said file
Create a .env file with an AbuseIPDB API key
Run python file_name
Install prompted necessary dependencies
Run python file_name
Watch as IPs try to scan your server, and see the firewall take action!
