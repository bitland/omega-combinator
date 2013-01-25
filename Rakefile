#
# Copyright (c) 2013 Hal Brodigan (postmodern.mod3 at gmail.com)
#
# This file is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This file is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this file.  If not, see <http://www.gnu.org/licenses/>.
#

require 'rake/clean'
require 'net/http'
require 'rack'

CLEAN.include('html.pcap')
PORT = 8080
HTML = 'file.html'
PCAP = HTML.chomp('.html') + '.pcap'

desc "Creates a pcap for #{HTML}"
file PCAP => HTML do
  unless Process.uid == 0
    abort "Please run with sudo. `sudo rake #{PCAP}`"
  end

  Thread.new do
    Rack::Server.start(
      :app       => Rack::Directory.new('.'),
      :Port      => PORT,
      :Host      => 'localhost'
    )
  end
    
  puts ">>> Starting tcpdump ..."
  tcpdump = fork do
    exec "tcpdump -i lo -w #{PCAP} 'port #{PORT}'"
  end
      
  sleep 1
    
  puts ">>> Requesting #{HTML} ..."
  Net::HTTP.get(URI::HTTP.build(
    :host => 'localhost',
    :port => PORT,
    :path => "/#{HTML}"
  ))

  puts ">>> Stopping tcpdump ..."
  Process.kill('INT',tcpdump)
end
