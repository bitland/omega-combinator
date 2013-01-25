require 'rake/clean'
require 'net/http'
require 'rack'

CLEAN.include('html.pcap')
PORT = 8080
HTML = 'file.html'
PCAP = HTML.chomp('.html') + '.pcap'

desc "Creates a pcap for #{HTML}"

file PCAP => HTML do
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