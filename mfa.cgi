#!/usr/bin/env /home/rvm/.rvm/bin/ruby

# TODO
# Add support for other AWS accounts
# Session db (and move data into it so hackery is harder)
# More Squidward

puts("Content-type: text/html\n\n")

require 'rubygems'
require 'aws-sdk'
require 'base64'
require 'cgi'
require 'sdbm'
require 'json'
require 'shellwords'

def vfind(vc, str) # Find an IAM virtual device given the login
   strlen = str.length
   vc.each { |v|
      sn = v.serial_number
      tail = sn[-strlen, strlen]
      if (tail == str) then return v end
   }
   return nil
end

def loadsession
   sid = @c.params['sid'][0] || (0...40).map{(65+rand(26)).chr}.join
   SDBM.open("/tmp/session.dbm") do |sdb|
      if (sdb.key?(sid)) then
         @S = JSON.parse(sdb[sid])
      else
         @S = { "sid" => sid, "remoteaddr" => ENV['REMOTE_ADDR'] }
      end
   end
end

def savesession
  SDBM.open("/tmp/session.dbm") do |sdb|
     sdb[@S['sid']] = @S.to_json
  end
end

def deletesession
   SDBM.open("/tmp/session.dbm") do |sdb|
      sdb.delete(@S['sid'])
   end
end

@c = CGI.new

# TODO: Change this for private IPS!
#allowed = ["65.204.229.11", "208.29.163.248", "72.220.74.197", "10.181.71.217"]
remoteaddr = ENV['REMOTE_ADDR']

#if (not allowed.include?(remoteaddr)) then
#   puts("#{remoteaddr} forbidden")
#   exit()
#end

loadsession()

login = @S['login'] || @c.params['login'][0]
if (login) then login = login.tr('^A-Za-z0-9+=,.@_-', '') end
if (login) then login.downcase! end
password = @S['password'] || @c.params['password'][0] 
code1 = @c.params['code1'][0] 
code2 = @c.params['code2'][0] 
userpass = @c.params['pass'][0] 

AWS.config({ # Add the credentials for your AWS account here
   :access_key_id => "",
   :secret_access_key => ""
})

@iam = AWS::IAM.new 
@v = @iam.virtual_mfa_devices

if (code1) then
   t = vfind(@v, login)
   # puts("found '" + t.serial_number + "'<BR>")
   begin # This will actually raise an error if it fails!!!
      result = t.enable(login, code1, code2) 
      puts("Your MFA makes you the envy of your peers. Live long, and prosper.<BR>")
      puts("<img title='Good Work. You are looked up to and approved by your peers.' alt='Good Work. You are looked up to and approved by your peers.' src=/hooray.jpg><BR>")
      puts("<BR>You can log in at <a target=\"signin\" href=https://" + @iam.account_alias + ".signin.aws.amazon.com/console>https://" +
           @iam.account_alias + ".signin.aws.amazon.com/console</a><BR>")
      puts("Your login is: " + login)
      #if (password == "[Your already set password]") then 
      #   puts("Because this IAM account already existed, I didn't change the password you already had set.")
      #else
         puts("<h3>Your password is: " + password + "</h3>")
         puts "Please feel free to change that in the AWS console to something easy to remember, but hard to guess.<BR>"
         u = @iam.users[login]
         u.login_profile.password = password
      #end
      deletesession()
      exit
   rescue
      puts("No luck - you may have made a typo, or simply waited too long.")
      puts("Let's try again - you'll need to delete your current MFA entry on your device, and re-scan the code...<BR>")
      t.delete
      #if (password != "[Your already set password]") then
         u = @iam.users[login]
         u.login_profile.password = password
      #end
   end
end

if (login) then
   IO.popen(["wget", "--quiet", "-O", "-", "--http-user=#{login}", "--http-password=#{userpass}", "https://insight.intuit.com/Pages/Home.aspx"]) { |f|
      @authenticated = f.read }
   if (@authenticated) then
      @S['login'] = login
      puts("<h1>Step 1 - create MFA for '#{login}'</h1>")
      u = @iam.users[login]
      if (not u.exists?) then # user does not exist, create them
         u = @iam.users.create(login)
      end
      @S['password'] = (0...8).map{(65+rand(26)).chr}.join
      admingroup = nil
      @iam.groups.each { |group| if (group.name == "Admins") then admingroup = group end }
      admingroup.users.add(u)
      t = vfind(@v, login)
      begin
         t.delete
      rescue
      end
      t = @v.create(login) # Create the MFA 
      q64 = Base64.encode64(t.qr_code_png)
      puts("<BR><font color='red'>Quickly now,</font> Please Scan the QR code with your virtual MFA device.<BR>")
      puts('<img src="data:image/png;base64,' + q64 + '" />')
      puts("<BR>Please enter the next two codes your device generates:<BR>")
      puts("<form method=POST>")
      puts("<input name=code1><input name=code2>")
      puts("<input type=hidden name=sid value=#{@S['sid']} />")
      puts("<input type=submit name=submit value='MFA me!' />")
      puts("</form>")
      savesession()
      exit
   else
      puts("<h3>Authentication Failed</h3>\n")
   end
end

puts("<table border=0><tr><td>")
puts("<h3>PLEASE READ:</h3>")
puts("This page will create an MFA-enabled IAM account (or replace MFA on an existing account)<BR>")
puts("in the Public Cloud Sandbox, yay!<BR>")
puts("<B>Before you begin</B>, you'll need to download and install Compatible MFA software for your Smartphone!<BR>")
puts("<a href=https://itunes.apple.com/us/app/google-authenticator/id388497605><img title='Apple App Store' alt='Apple App Store' width=180 src=/appleapp.png></a>")
puts("<a href=https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2><img title='Google Play' alt='Google Play' width=155 src=/androidapp.png></a>")
puts("or <a href=http://en.wikipedia.org/wiki/Google_Authenticator>Blackberry, Windows phone, and other platforms</a><BR>")
#puts("You can find a compatible authenticator for <a href=https://itunes.apple.com/us/app/google-authenticator/id388497605>Apple Devices</a>, ")
#puts("<a href=https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2>Android Devices</a>, or <a href=http://en.wikipedia.org/wiki/Google_Authenticator>Blackberry, Windows phone, and other platforms</a>.<BR>")
puts("Note that your authenticator must support QR codes - I know the ones for Android and iPhone do, the others are iffy...<BR>")
puts("<font color='red'>If you take longer than a minute to enter the two followup codes, the process will fail.</font><BR>")
puts("That minute goes <i>really quick</i>. Be Ready - have your app open and scanning for a barcode before you hit 'Go'<BR>")
puts("<BR>When you're ready, type your Intuit Login name and password (you use them for Outlook), and hit 'Go'<BR>")
puts("<form method=POST>Login:<input name=login>   Pass:<input type=password name=pass> <input type=submit value='Go!'><input type=hidden name=sid value=#{@S['sid']} /></form>")
puts("</td><td>")
puts("<img title='I am Squidward, and I approve of this message.' alt='I am Squidward, and I approve of this message.' align=right border=0 src=/squidward-looking.png>")
puts("</td></tr></table>")
