require 'socket'

TYPE_OPEN          = 1
TYPE_UPDATE        = 2
TYPE_NOTIFICATION  = 3
TYPE_KEEPALIVE     = 4
TYPE_ROUTE_REFRESH = 5

TYPES = {
  1 => "TYPE_OPEN",
  2 => "TYPE_UPDATE",
  3 => "TYPE_NOTIFICATION",
  4 => "TYPE_KEEPALIVE",
  5 => "TYPE_ROUTE_REFRESH",
}

def parse(data)
  packet = {}
  packet[:marker], packet[:length], packet[:type], data = data.unpack("A16nca*")

  if(packet[:type] == TYPE_NOTIFICATION)
    packet[:major_error], packet[:minor_error], packet[:extra_data] = data.unpack("cca*")
  elsif(packet[:type] == TYPE_OPEN)
    packet[:version], packet[:my_as], packet[:hold_time], packet[:bgp_identifier], packet[:opt_len], packet[:optional] = data.unpack("cnnNca*")
  elsif(packet[:type] == TYPE_KEEPALIVE)
    packet[:extra_data] = data
  elsif(packet[:type] == TYPE_UPDATE)
    data.split(//).each do |x|
      print '\x0x%02x' % x.ord
    end
    puts()

    packet[:unfeasible_length], data = data.unpack("na*")
    packet[:unfeasible],        data = data.unpack("a#{packet[:unfeasible_length]}a*")
    packet[:path_length],       data = data.unpack("na*")
    packet[:path],              data = data.unpack("a#{packet[:path_length]}a*")
    packet[:reachablity]             = data
  else
    packet[:unparsed] = data.unpack("H*")
    puts("WARNING: Unknown type: #{packet[:type]}")
  end

  return packet
end

def packet_to_s(packet)
  return("[[#{TYPES[packet[:type]]}]] :: #{packet.inspect}")
end

def send(s, type, data)
  packet = ["\xFF" * 16, data.length + 19, type].pack("a*nc") + data

  puts("OUT :: #{packet_to_s(parse(packet))}")
  s.write(packet)
end

def send_open(s, version, my_as, hold_time, bgp_identifier, optional = nil)
  optional = optional || ""
  data = [version, my_as, hold_time, bgp_identifier, optional.length, optional].pack("cnnNca*")
  send(s, TYPE_OPEN, data)
end

def send_update(s)
  unfeasible_routes = ""

  path = [0x40, # flags
          0x01, # type code = ORIGIN
          0x01, # length
          0x00, # IGP
  ].pack("cccc")

  path += [ 0x40, # flags
            0x02, # type code = AS_PATH
            0x04, # length
            0x02, # path segment type
            0x10, # path segment length (in ASes)
            0xf00d, # ASes
  ].pack("cccccn")

  path += [ 0x40, # flags
            0x03, # type code = NEXT_HOP
            0x04, # length
            0x01020304, # ip address
  ].pack("cccN")

  reachability = "\x20\x68\x50\x73\xb7"

  data = [unfeasible_routes.length, unfeasible_routes, path.length, path, reachability].pack("na*na*a*")
  send(s, TYPE_UPDATE, data)
end

s = TCPSocket.new("192.168.1.104", ARGV[0])

send_open(s, 4, 12345, 100, 0x01020304, "\x02\x06\x01\x04\x00\x01\x00\x01")
send_update(s)

puts("IN  :: " + packet_to_s(parse(s.recv(1024))))
puts("IN  :: " + packet_to_s(parse(s.recv(1024))))
puts("IN  :: " + packet_to_s(parse(s.recv(1024))))


puts("IN  :: " + packet_to_s(parse(s.recv(1024))))

