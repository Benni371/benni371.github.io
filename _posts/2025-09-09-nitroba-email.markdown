---
layout: post
title:  "Nitroba - Email Harassment"
date:   2025-09-09 12:18:34 -0400
tags: dfir digital-corpora
author: Benshkies
---

# Scenario
SOURCE: [Digital Corpora](https://digitalcorpora.org/corpora/scenarios/nitroba-university-harassment-scenario/)
(Note: Because packet capture files contain timestamps for each packet, this scenario needs to have a date and time when it takes place. This scenario takes place in Summer 2008. The date and time stamps are not relevant in solving the problem set.)

You are a security administrator at the prestigious (and fictional) Nitroba State University.

Nitroba’s IT department received an email from Lily Tuckrige, a teacher in the Chemistry Department. Tuckrige has been receiving harassing emails and she suspects that they are being sent by a student in her class Chemistry 109, which she is teaching this summer. The email was received at Tuckridge’s personal email account, lilytuckrige@yahoo.com. She took a screenshot of the web browser and sent it in.

The system administrator who received the complaint wrote back to Tuckridge that Nitroba needed the full headers of the email message. Tuckridge responded by clicking the “Full message headers” button in Yahoo Mail and sent in another screen shot, this one with mail headers.

The mail header shows that the mail message originated from the IP address 140.247.62.34, which is a Nitroba student dorm room. Three women share the dorm room. Nitroba provides an Ethernet connection in every dorm room but not Wi-Fi access, so one of the women’s friends installed a Wi-Fi router in the room. There is no password on the Wi-Fi.

Because several email messages appear to come from the IP address, Nitroba decides to place a network sniffer on the ethernet port. All of the packets are logged. On Monday 7/21 Tuckridge received another harassing email. But this time instead of receiving it directly, the perpetrator sent it through a web-based service called “willselfdestruct.com.” The website briefly shows the message to Tuckridge, and then the website reports that the “Message Has Been Destroyed.”

You have been given the screen shots, the packets that were collected from the Ethernet tap, and the Chem 109 roster. Your job is to determine if one of the students in the class was responsible for the harassing email and to provide clear, conclusive evidence to support your conclusion.

# Summary of What We Know
Target: Lily Tuckrige
- Email: lilytuckrige@yahoo.com
Harasser:
- IP 140.247.62.34
- nobody[@]nitroba.org
- 3 women share the dorm room that the ip connects to: Alice, Barbara, Candice
- The room has a WiFi router installed by Barbaras boyfriend Kenny
- 7/21 email sent from willselfdestruct[.]com
- 3 Devices: A mac desktop, a Desktop PC, and  a laptop
![Nitroba Diagram](\assets\images\nitroba-diagram.png)

# Investigation
Using the filter on the dorm ip: 140.247.62.34 we can find a one device connecting to it.
## Apple Mac Device: 
- MAC: 00:17:f2:e2:c0:ce
- IP: 192.168.15.4

The Mac Device made a DNS query to www.willselfdestruct[.]com 

| Src IP       | Dst IP        | Protocol | Info                                              |
| ------------ | ------------- | -------- | ------------------------------------------------- |
| 192.168.15.4 | 192.168.1.254 | DNS      | Standard query 0x0000 A www.willselfdestruct.com) |

URL: hxxp://www[.]willselfdestruct.com/\<redacted\> found. Examining packets related to this url filtering on a POST request we find the HTML form submitted with the hostile message.

| Src IP       | Dst IP       | Protocol | Info                                                            |
| ------------ | ------------ | -------- | --------------------------------------------------------------- |
| 192.168.15.4 | \<redacted\> | HTTP     | GET \<redacted\>HTTP/1.1                                        |
| 192.168.15.4 | \<redacted\> | HTTP     | POST \<redacted\> HTTP/1.1  (application/x-www-form-urlencoded) |


![HTML FORM](\assets\images\html-form-selfdestruct.png)

This is conclusive evidence that this device created and sent this self destruct message but we need to find who this IP belongs to.

Another email sent using sendanonymousemail.net/send.php as well as a new email "the_whole_world_is_watching@nitroba.org"

| Src IP       | Dst IP       | Protocol | Info                                                         |
| ------------ | ------------ | -------- | ------------------------------------------------------------ |
| 192.168.15.4 | \<redacted\> | HTTP     | POST /send.php HTTP/1.1  (application/x-www-form-urlencoded) |

Hotel information used by the harasser:

| Src IP       | Dst IP       | Protocol | Info                                                                                                                                        |
| ------------ | ------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| 192.168.15.4 | \<redacted\> | HTTP     | POST /App/ViewHotelDetails?z=b97d&r=aq&availabilityRequestOnly=true&fromDetailsLightbox=false HTTP/1.1  (application/x-www-form-urlencoded) |

It looks like the user signed into their gmail at one point. Looking for gmail we see that there are a couple packets with user id present in the cookies. 

| Src IP       | Dst IP       | Protocol | Info                                                                                                                                                                                                                                                                                                          |
| ------------ | ------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 192.168.15.4 | \<redacted\> | HTTP     | GET /calendar/render?utm_campaign=en&utm_source=en-ha-na-us-bk&utm_medium=ha&utm_term=google+calendar&auth=DQAAAHAAAAA2jRol_d6eqNta6cIsYOASXiZFYMBTwdPcfzNQ24Qd0nZk837TiFwZuF-_zmFJv9UCMI1Hau3HvfR1-t3bfWj7AesmzsMkDPijjxRrfQdoDLmTsZFz_eXV7ghw6iFvaUuLKeDM4CzM1Z7yPw9jP4-V&**gausr**=\<REDACTED\>** HTTP/1.1 |

\<REDACTED EMAIL\> is none other than \<REDACTED\> from Lily Tuckrige's class

If you want the answers or would like to know more about my thought process, feel free to reach out to me on [LinkedIn](https://www.linkedin.com/in/koy-bennion/)