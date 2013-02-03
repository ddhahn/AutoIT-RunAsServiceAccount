This script will run a command as the specified user, making sure
the command is elevated to the highest privilege on the system

It does this by modifying the local security policy to allow the specified user
the ability to log on as a service, then uses that logon type to get
"system" level privileges. 

This script must be run as system to work, so they're no magic here as far as 
elevating privileges on a Windows system. I wrote this originally because
we needed a way to run a command via LANDesk as another admin user, besides SYSTEM.
Some installers weren't designed to work as system.