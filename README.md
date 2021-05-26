<p># CloudflareDDNS</p>
<p>Hiya!&nbsp;</p>
<p>As you can probably tell from the state of it - this was my first real attempt at writing code.. I spent about an hour or two watching python basics videos then set to work with google as my friend!</p>
<p>It&apos;s purpose is simple - to fetch your current external IP address and then update your Cloudflare DNS record accordingly.</p>
<p>The reason for doing so is that my ISP will only provide a static IP to a business user, meaning I&apos;m stuck with a dynamic one. I run a Plex server from home (among other things) and should the IP be changed by my ISP I would want it to be updated ASAP and automatically. I currently have the script on my raspberry Pi set as a cron job to run every 15 minutes.</p>
<p>To get started simply pop in your domain name, record type (A / AAAA) and <a href="https://developers.cloudflare.com/api/tokens/create">Cloudflare API Token</a> (sorry - keys not supported) and run the script manually.</p>
<p>It should <strong>hopefully</strong> message in the terminal if something has gone amiss... Once it&apos;s performed one successful update, it should be OK to schedule using <a href="https://crontab.guru/">cron</a>.</p>
<p>I may well expand on this in future and/or tidy it up as at present I&apos;m more or less googling E V E R Y T H I N G as I go haha. But it&apos;ll do for now.&nbsp;</p>
<p>If you have any thoughts or suggestions give me a shout.</p>
<p>Cheers!</p>
