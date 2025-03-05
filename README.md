# Zodimac
In our new age of internet supremacy, do we still know what is going on within our own network? Like, what machines are actually enjoying our company? Why is our printer not working again? Is there really symbiosis between our router and the smart robot cleaning our floors? 

This small python executable helps with lightening the mood, and to encourage you to look at all the devices present in your network (a bit of practical security practice). While also finding out how their current months cycle is in line with yours. Is there true enlightenment in your relationship. 

You can download the executable (I know I tried) or pull the codebase and run it within your own means. 
Zodimac will pull all machines in your local network, find out their unique genotype known as a MAC adress and return you a small overview of their current zodiac, their IP and the information that is present from the small pull. There are 2 versions; A standalone executable without admin access (gives less specific information on the device) and a second version that needs packages and local admin access. 

## How to run:
### Zodimac standalone
Download the executable (it looks dangerous but please look at the code to see how it is very safe), and run it on your machine. It might ask you to make sure to trust it through security & privacy status. It should open a python script and return some lovely feature cards in the form of pop up windows on all your co-internet-habitation devices. 

All the names you'll see are names that are given to your devices themselves and do not specifically need to be OS specifice (for example, i've named my tv: samsung-annoyance. It will show that name instead of tv. so it is a bit dependable). So also if it doesn't return a name, or a weird string, go and check out your router data!

The idea is that you can use this information to go more into a deep dive yourself (like logging into your router and see what these devices are and maybe even blocking it). The first step would be to access your router (there should be a how to on the back of your router), but mostly happens if you go to 192.168.1.1 in your browser (where you normally type in google.com). From there on it is up to you. 

### Zodimac_sudo_nmap
This one is a bit more tricky, You can pull the repository of the script and run it from the terminal (using python3 Zodimac_sudo_nmap.py while in the map that you have downloaded it to). It will need to have a base python3.13 installation as well as nmap (brew install nmap). It will request a Sudo (admin) password so it can actually do a retraceable DNS call. 

Afterwards the script loses access to the password (sudo is not being saved anywhere), and you'll be left with a bit more in depth (hopefully) information on the active devices in your network. From here on I'd recommend also checking out your router and try to get some intel on what else is there on your network. 

## Final takeaways
This is a combination of an art project as well as a way of getting people to understand bettter what is happening on their network and encourage everybody to see if their network is secure and safe. 

Thank you all for the use and love.
