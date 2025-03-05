# Zodimac
In our new age of internet supremacy, do we still know what is going on within our own network? Like, what machines are actually enjoying our company? Why is our printer not working again? Is there really symbiosis between our router and the smart robot cleaning our floors? 

This small python executable helps with lightening the mood, and to encourage you to look at all the devices present in your network (a bit of practical security practice). While also finding out how their current months cycle is in line with yours. Is there true enlightenment in your relationship. 

## How to run:
### Zodimac standalone
On this page, on the green "code" button you can click and find "download zip". When it is downloaded you'll have to make sure to unzip it (this is automatically done sometimes as well). You'll see maps that you can open in your finder/file explorer. If you open the map dist there will be a file called: zodimac (which will be a unix executable). If you double click on that you'll be able to run the application. 

It will tell you that the file is dangerous (I understand this but there is no other way for everyone to run it easily without using python). So you'll have to go into the security & privacy to say that this application is okay for you to run. 

This will open a lovely terminal screen that will run a tkinter GUI for you to see what beautifull things are living in your current network!

All the names you'll see are names that are given to your devices themselves and do not specifically need to be OS specifice (for example, i've named my tv: samsung-annoyance. It will show that name instead of tv. so it is a bit dependable). So also if it doesn't return a name, or a weird string, go and check out your router data!

The idea is that you can use this information to go more into a deep dive yourself (like logging into your router and see what these devices are and maybe even blocking it). The first step would be to access your router (there should be a how to on the back of your router), but mostly happens if you go to 192.168.1.1 in your browser (where you normally type in google.com). From there on it is up to you. 

### Zodimac_sudo_nmap
This one is a bit more tricky, You can pull the repository of the script and run it from the terminal (using python3 Zodimac_sudo_nmap.py while in the map that you have downloaded it to). It will need to have a base python3.13 installation as well as nmap (brew install nmap). It will request a Sudo (admin) password so it can actually do a retraceable DNS call. 

Afterwards the script loses access to the password (sudo is not being saved anywhere), and you'll be left with a bit more in depth (hopefully) information on the active devices in your network. From here on I'd recommend also checking out your router and try to get some intel on what else is there on your network. 

## Final takeaways
This is a combination of an art project as well as a way of getting people to understand bettter what is happening on their network and encourage everybody to see if their network is secure and safe. 

Thank you all for the use and love.
