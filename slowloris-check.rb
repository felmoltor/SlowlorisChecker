#!/usr/bin/ruby

################################################################################
# Ya que el script de slowloris de nmap no funciona                            #
# he dedidido hacer la misma prueba de una forma un poco cutre pero se basa en #
# la misma filosofía:                                                          #
#                                                                              #
# Abrimos dos conexiones al mismo tiempo al servidor:                          #
# 1 - Conexión de control: Esta conexión no enviará nada a parte de un par de  #
# cabeceras y esperará a que de timeout el servidor.                           #
# 2 - Conexión de retraso: Esta conexión se crea a la misma vez que la primera,#
#     envia las mismas cabeceras, espera 10 segundos y envia una cabecera más  #
#     al servidor. Espera a que de timeout el servidor.                        #
#                                                                              #
# Si hay una diferencia de tiempos entre el timeout 1 y el 2 de 10 segundos o  #
# más, entonces podemos concluir que el servidor es vulnerable a este ataque,  #
# ya que una conexión podrá mantenerse ocupada en el servidor mientras se      #
# envien cabeceras cada 10 segundos.                                           #
#                                                                              #
# Explicación completa en https://community.qualys.com/blogs/securitylabs/2011 #
# /07/07/identifying-slow-http-attack-vulnerabilities-on-web-applications      #
################################################################################
# TODO: SSL sockets                                                            #
################################################################################

require 'socket'
require 'base64'
require 'optparse'
# require 'openssl'

$version = "1.0"
$author = "Felipe Molina"
$twitter = "@felmoltor"
$email = "felmoltor@gmail.com"
$year = "2012"
$license = """
= 'Slowloris' and 'Slow POST' vulnerability check for HTTP servers
=    Copyright (C) #{$year}  #{$author}
=
= This program is free software: you can redistribute it and/or modify
= it under the terms of the GNU General Public License as published by
= the Free Software Foundation, either version 3 of the License, or
= (at your option) any later version.
=
= This program is distributed in the hope that it will be useful,
= but WITHOUT ANY WARRANTY; without even the implied warranty of
= MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
= GNU General Public License for more details.
= 
= You should have received a copy of the GNU General Public License
= along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
# ========================

# Printing correct usage
def printUsage
    puts "Usage: "
    puts " #{__FILE__} <hostname> [<port>] [<url_with_post>] [-s]"
end

def showProgramInfo
    puts "========================================"
    puts "= Program: #{__FILE__}:"
    puts "= - Version: #{$version}"
    puts "= - Author: #{$author} (https://twitter.com/#{$twitter}, #{$email})"
    puts "========================================"
    puts "= #{$license}"
    puts "========================================"
end

# ========================

# Measuring execution time
def time
  start = Time.now
  yield
  Time.now - start
end

def createSocket(ssl)
    if ssl
        OpenSSL::SSL::VERIFY_NONE
    else

    end
    socket
end

# ========================

def parseOptions
    opts = {:hostname => "localhost", :port => 80, :ssl => false, :auth => "", :useragent => "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0;)",:delay => 10, :delay_error => 0.5, :posturl => "/"}

    parser = OptionParser.new do |opt|
        opt.banner = "Usage: #{__FILE__} [options]"
        opt.separator ""
        opt.separator "Specific options: "

        opt.on("-s [HOSTNAME]","--server [HOSTNAME]","Name of the host to check for Slowloris and Slow POST (default: localhost)") do |hostname|
            opts[:hostname] = hostname
        end
        opt.on("-p [PORTNUMBER]","--port [PORTNUMBER]","Port number where the HTTP server is listening (default: 80)") do |port|
            opts[:port] = port
        end
        opt.on('-S','--ssl', 'The target web uses ssl (default: false)') do 
            opts[:ssl] = true
        end
        opt.on('-a [USER:PASSWORD]','--auth [USER:PASSWORD]', 'If the web needs BASIC authentication for some URLs to test (Format user:password)') do |auth|
            opts[:auth] = Base64.encode64(auth).chomp
        end
        opt.on('-d [SECONDS]','--delay [SECONDS]', 'Number of seconds we''ll wait to send the second part of header of post (default: 10 seconds)') do |delay|
            opts[:delay] = delay.to_i
        end
        opt.on('-U [USERAGENT]','--user-agent [USERAGENT]', 'User Agent to show to the target server') do |ua|
            opts[:useragent] = ua
        end
        opt.on('-P [POSTURL]','--post-url [POSTURL]', 'To test the Slow Post you should specify the path where the server is accepting POST') do |url|
            opts[:posturl] = url
        end
        opt.on('-V','--version', 'Shows current version of the program, author and contact details') do
            showProgramInfo
            exit
        end
        opt.on("-h","--help", "Print help and usage information") do
            puts parser
            exit
        end 
    end # del parse do

    begin
        parser.parse($*)
        puts "Puerto, ssl: #{opts[:port]}, #{opts[:ssl]}"
        if (opts[:port].to_i == 80 and opts[:ssl])
            opts[:port] = 443
        end
    rescue OptionParser::InvalidOption
        puts "Error: Some specified options where invalid"
        puts parser
        exit
    end
    opts
end

# ========================

##############################
# GLOBAL (DEMONIC) VARIABLES #
##############################

t_control_head = 0
t_delay_head = 0
t_control_post = 0
t_delay_post = 0
auth_string = ""
threads = ["control","delay"]
ts = []


########
# MAIN #
########

# Receive options from command line
options = parseOptions
puts
puts "========================================="
puts "|= Executing with the following options ="
puts "========================================="
puts "|"
options.each {|k,v|
    puts "| - #{k}: #{v}"
}
puts "========================================="

auth_header="Authentication: Basic #{options[:auth]}\r\n" if options[:auth].size > 0

# Detecting slowloris
slow_headers_1=%w(
GET / HTTP/1.1
Host: #{options[:hostname]}
#{auth_header}User-Agent:#{options[:useragent]}
Connection: keep-alive
)
slow_headers_2="X-wait-for-me: Thank you"

# Detecting slow POST
slow_post_1=%w(
POST #{options[:posturl]} HTTP/1.1
Host: #{options[:hostname]}
#{auth_header}User-Agent:#{options[:useragent]}
Connection: keep-alive
Keep-Alive: 300
Content-Type: application/x-www-form-urlencoded
Content-Length: 512
Accept: text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5

mgs=msg1&)
slow_post_2="more_msg=more&"

# ==============================
# === SLOW HEAD (slowloris) ====
# ==============================

puts
puts "==================================="
puts "== Testing slow head (slowloris) =="
puts "==================================="
puts

for thread in threads
    ts << Thread.new(thread) {|tname|
        if tname == "control"
            # Control thread
            t_control_head = time do
                    begin
                        s_control = TCPSocket.new(options[:hostname],options[:port])
                        s_control.write(slow_headers_1)
                        response = s_control.recv(1024) # Running until timeout (408?)
                    rescue Errno::ECONNREFUSED
                        $stderr.puts "Error. Conexion refused. Check if hostname #{options[:hostname]} and port #{options[:port]} is correct"
                        exit
                    rescue Errno::ECONNRESET
                        $stderr.puts "El servidor #{options[:hostname]} reseteo la conexion"
                    end
            end
        elsif tname == "delay"
            # Delay thread
            t_delay_head = time do
                    begin
                        s_delay = TCPSocket.new(options[:hostname],options[:port])
                        s_delay.write(slow_headers_1)
                        sleep(options[:delay])
                        s_delay.print(slow_headers_2)
                        response = s_delay.recv(1024)
                    rescue Errno::ECONNREFUSED
                        $stderr.puts "Error. Conexion refused. Check if hostname #{options[:hostname]} and port #{options[:port]} is correct"
                        exit
                    rescue Errno::ECONNRESET
                        $stderr.puts "El servidor #{options[:hostname]} reseteo la conexion"
                    end
            end
        end
    }
end

ts.each {|t| t.join }

time_diff = t_delay_head - t_control_head
puts "# Timeout en hebra de control: #{t_control_head}"
puts "# Timeout en hebra de delay: #{t_delay_head}"
puts "# We got hanged the server waiting for more Headers during #{time_diff.round(3)} seconds"
puts 
if time_diff > options[:delay]
    puts "## VULNERABLE to slowloris!"
elsif ((time_diff > (options[:delay] - options[:delay_error])) and (time_diff < (options[:delay] + options[:delay_error])))
    puts "## PROBABLY Vulnerable to slowloris!"
else
    puts "## NOT vulnerable to slowloris"
end

puts
puts "==================================="
puts "========= Testing slow POST ======="
puts "==================================="
puts

for thread in threads
    ts << Thread.new(thread) {|tname|
        if tname == "control"
            # Control thread
            t_control_post = time do
                    begin
                        s_control = TCPSocket.new(options[:hostname],options[:port])
                        s_control.write(slow_post_1)
                        s_control.recv(1024) # Running until timeout (504?)
                    rescue Errno::ECONNREFUSED
                        $stderr.puts "Error. Conexion refused. Check if hostname #{options[:hostname]} and port #{options[:port]} is correct"
                        exit
                    rescue Errno::ECONNRESET
                        $stderr.puts "El servidor #{options[:hostname]} reseteo la conexion"
                    end
            end
        elsif tname == "delay"
            # Delay thread
            t_delay_post = time do
                    begin
                        s_delay = TCPSocket.new(options[:hostname],options[:port])
                        s_delay.write(slow_post_1)
                        sleep(options[:delay])
                        s_delay.print(slow_post_2)
                        s_delay.recv(1024)
                    rescue Errno::ECONNREFUSED
                        $stderr.puts "Error. Conexion refused. Check if hostname #{options[:hostname]} and port #{options[:port]} is correct"
                        exit
                    rescue Errno::ECONNRESET
                        $stderr.puts "El servidor #{options[:hostname]} reseteo la conexion"
                    end
            end
        end
    }
end

ts.each {|t| t.join }

time_diff = t_delay_post - t_control_post
puts "# Timeout en hebra de control: #{t_control_post}"
puts "# Timeout en hebra de delay: #{t_delay_post}"
puts "# We got hanged the server for more POST values during #{time_diff.round(3)} seconds"
puts
if (time_diff > options[:delay])
    puts "## VULNERABLE to Slow POST!"
elsif ((time_diff > (options[:delay] - options[:delay_error])) and (time_diff < (options[:delay] + options[:delay_error])))
    puts "## PROBABLY Vulnerable to Slow POST!"
else
    puts "## NOT vulnerable to Slow POST"
end
puts

