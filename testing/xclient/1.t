
# swaks  -s 162.150.58.173 --auth-user <UID> --auth-password <password> -f
# test_sender@cable.comcast.com -t test_rcpt_123@comcast.net --header
# 'Subject: 20141212' --xclient "ADDR=25.25.25.25 NAME=bob.comcast.net"
# === Trying 162.150.58.173:25...
# === Connected to 162.150.58.173.
# <-  220 2.0.0 mdpapp-ch2-1p.sys.comcast.net ESMTP ecelerity 4.1.0.46072
# r(Core:4.1.0.2) Wed, 28 Jan 2015 21:57:14 +0000
#  -> EHLO aa-tools-ch2-01p.novalocal
# <-  250-mdpapp-ch2-1p.sys.comcast.net says EHLO to 162.150.4.90:38147
# <-  250-XREMOTEIP
# <-  250-XCLIENT
# <-  250-AUTH=LOGIN
# <-  250-AUTH LOGIN
# <-  250-8BITMIME
# <-  250-ENHANCEDSTATUSCODES
# <-  250 PIPELINING
# *** Host did not advertise XCLIENT
#  -> QUIT
# <-  221 2.3.0 mdpapp-ch2-1p.sys.comcast.net closing connection
# === Connection closed with remote host.


  send_line("220 2.0.0 mdpapp-ch2-1p.sys.comcast.net ESMTP ecelerity 4.1.0.46072 r(Core:4.1.0.2) Wed, 28 Jan 2015 21:57:14 +0000");

  get_line(); # EHLO

send_line("250-mdpapp-ch2-1p.sys.comcast.net says EHLO to 162.150.4.90:38147");
send_line("250-XREMOTEIP");
# send_line("250-XCLIENT NAME ADDR");
send_line("250-XCLIENT");
send_line("250-AUTH=LOGIN");
send_line("250-AUTH LOGIN");
send_line("250-8BITMIME");
send_line("250-ENHANCEDSTATUSCODES");
send_line("250 PIPELINING");

  get_line(); # XCLIENT
  send_line("221 SERVER closing connection");
